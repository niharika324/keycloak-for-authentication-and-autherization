from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from starlette.types import ASGIApp
from typing import Callable, Optional, List, Tuple
from datetime import datetime, timezone
from fastapi import HTTPException
from starlette.status import HTTP_401_UNAUTHORIZED, HTTP_500_INTERNAL_SERVER_ERROR
import logging, traceback, uuid

from auth.service import AuthService

logger = logging.getLogger("uvicorn.error")


def _log_exc(context: str, exc: Exception) -> str:
    err_id = str(uuid.uuid4())
    logger.error("[%s] System exception %s: %r\n%s", context, err_id, exc, traceback.format_exc())
    return err_id


# Singleton for your service wrappers (introspect / refresh_tokens)
_SERVICE_SINGLETON: Optional[AuthService] = None
def _svc() -> AuthService:
    global _SERVICE_SINGLETON
    if _SERVICE_SINGLETON is None:
        _SERVICE_SINGLETON = AuthService()
    return _SERVICE_SINGLETON


def _get_header(headers: List[Tuple[bytes, bytes]], name: str) -> Optional[str]:
    name_bytes = name.lower().encode("latin-1")
    for k, v in headers:
        if k.lower() == name_bytes:
            return v.decode("latin-1")
    return None


def _set_or_replace_header(
    headers: List[Tuple[bytes, bytes]], name: str, value: str
) -> List[Tuple[bytes, bytes]]:
    name_bytes = name.lower().encode("latin-1")
    new_headers = [(k, v) for (k, v) in headers if k.lower() != name_bytes]
    new_headers.append((name_bytes, value.encode("latin-1")))
    return new_headers


class AuthMiddleware(BaseHTTPMiddleware):
    """
    Passive auth-refresh middleware that delegates Keycloak calls to AuthService.
    Distinguishes:
      - expired token  -> 401 "Token is expired."
      - invalid token  -> 401 "Invalid token."
    And when expired + refresh present:
      - refresh ok     -> injects new Authorization and adds X-New-Access-Token / X-New-Refresh-Token
      - refresh fail   -> 401 "Access token expired and refresh failed (...error_id...)"
    """

    def __init__(self, app: ASGIApp):
        super().__init__(app)

    async def dispatch(self, request, call_next: Callable):
        scope = request.scope
        headers: List[Tuple[bytes, bytes]] = list(scope.get("headers", []))

        auth = _get_header(headers, "authorization")
        if not auth or not auth.lower().startswith("bearer "):
            # Public request or no token — pass through
            return await call_next(request)

        access_token = auth.split(" ", 1)[1].strip()

        # ---- 1) Introspect current token via your service ----
        is_expired = False
        try:
            info = _svc().introspect(access_token)  # wrapped SDK call
            active = bool(info.get("active"))

            if active:
                # Optionally double-check exp if present
                exp = info.get("exp")
                if isinstance(exp, (int, float)):
                    now = datetime.now(tz=timezone.utc).timestamp()
                    if exp < now:
                        is_expired = True
                if not is_expired:
                    # Token is fine -> continue
                    return await call_next(request)

            else:
                # Not active; try to decide expired vs invalid using 'exp' if available
                exp = info.get("exp")
                if isinstance(exp, (int, float)):
                    now = datetime.now(tz=timezone.utc).timestamp()
                    is_expired = exp < now
                else:
                    # No exp provided -> treat as invalid
                    is_expired = False

        except HTTPException as e:
            # Your service already formatted details (and may include error_id)
            if e.status_code == HTTP_401_UNAUTHORIZED:
                # Could be invalid/expired; without payload we treat as invalid
                return JSONResponse(status_code=401, content={"detail": "Invalid token."})
            return JSONResponse(status_code=e.status_code, content={"detail": e.detail})
        except Exception as e:
            err_id = _log_exc("middleware.introspect", e)
            return JSONResponse(
                status_code=HTTP_500_INTERNAL_SERVER_ERROR,
                content={"detail": f"Token check failed due to a system error (error_id={err_id})."},
            )

        # ---- 2) If expired, try to refresh; if invalid, return specific 401 ----
        if not is_expired:
            # Not active AND not expired => invalid token
            return JSONResponse(status_code=401, content={"detail": "Invalid token."})

        # Token is expired -> look for refresh token
        refresh_token = _get_header(headers, "x-refresh-token")
        if not refresh_token:
            cookie = _get_header(headers, "cookie") or ""
            for part in cookie.split(";"):
                if part.strip().startswith("refresh_token="):
                    refresh_token = part.strip().split("=", 1)[1]
                    break

        if not refresh_token:
            # Explicit expired message when no refresh is present
            return JSONResponse(status_code=401, content={"detail": "Token is expired."})

        # ---- 3) Attempt refresh via your service ----
        try:
            refreshed = _svc().refresh_tokens(refresh_token)
            new_access = refreshed.get("access_token")
            new_refresh = refreshed.get("refresh_token") or refresh_token
            if not new_access:
                raise RuntimeError("Keycloak refresh did not return an access_token")

            # Inject new Authorization header for downstream
            headers = _set_or_replace_header(headers, "authorization", f"Bearer {new_access}")
            scope["headers"] = headers

            from starlette.requests import Request as StarletteRequest
            new_request = StarletteRequest(scope, receive=request.receive)
            response = await call_next(new_request)

            # Expose new tokens to the client
            response.headers["X-New-Access-Token"] = new_access
            if new_refresh:
                response.headers["X-New-Refresh-Token"] = new_refresh
            return response

        except HTTPException as e:
            # Most likely 401 with detail from service; keep message explicit about refresh failure
            if e.status_code == HTTP_401_UNAUTHORIZED:
                return JSONResponse(status_code=401, content={"detail": "Access token expired and refresh failed."})
            return JSONResponse(status_code=e.status_code, content={"detail": e.detail})
        except Exception as e:
            err_id = _log_exc("middleware.refresh", e)
            return JSONResponse(
                status_code=HTTP_500_INTERNAL_SERVER_ERROR,
                content={"detail": f"Access token expired and refresh failed (error_id={err_id})."},
            )
