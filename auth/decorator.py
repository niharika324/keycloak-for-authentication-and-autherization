from fastapi import Security, HTTPException, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.status import (
    HTTP_401_UNAUTHORIZED,
    HTTP_403_FORBIDDEN,
    HTTP_500_INTERNAL_SERVER_ERROR,
)
from typing import Dict, Any, Callable, Optional, List
from functools import wraps
import inspect
import uuid
import logging, traceback

from auth.service import AuthService
import config

bearer_scheme = HTTPBearer(auto_error=False)
logger = logging.getLogger("uvicorn.error")

def _log_exc(context: str, exc: Exception) -> str:
    """
    Log unexpected exceptions with a unique error ID and return that ID.
    """
    err_id = str(uuid.uuid4())
    logger.error("[%s] System exception %s: %r\n%s", context, err_id, exc, traceback.format_exc())
    return err_id

def _get_service(request: Request) -> AuthService:
    """
    Resolve AuthService from app.state with system-exception handling.
    """
    try:
        svc = getattr(request.app.state, "auth_service", None)
        if svc is None:
            # Considered a system/setup problem → 500
            raise RuntimeError("AuthService not initialized on app.state.auth_service")
        return svc
    except HTTPException:
        # Bubble any explicit HTTP errors unchanged (rare here)
        raise
    except Exception as e:
        err_id = _log_exc("decorator._get_service", e)
        raise HTTPException(
            status_code=HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Authentication service unavailable (error_id={err_id}).",
        )

class AuthDecorator:
    @staticmethod
    def get_current_user(
        credentials: HTTPAuthorizationCredentials = Security(bearer_scheme),
        svc: AuthService = Depends(_get_service),
    ) -> Dict[str, Any]:
        """
        Resolve current user context from a Bearer token.
        - 401 for missing/invalid/expired token (expected auth failures)
        - 500 with error_id for unexpected/system failures
        """
        if not credentials or not credentials.credentials:
            raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Missing bearer token")

        token = credentials.credentials
        try:
            return svc.build_user_context_from_token(token)

        except HTTPException:
            # If the service raised a specific HTTP error (likely 401), bubble it up.
            raise
        except Exception as e:
            # Unexpected/system failure (SDK/network/config/etc.)
            err_id = _log_exc("decorator.get_current_user", e)
            raise HTTPException(
                status_code=HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Unable to validate token due to a system error (error_id={err_id}).",
            )

    @staticmethod
    def check_user_access(
        required_role: str,
        client_id: Optional[str] = None,
    ):
        """
        Enforce access based on a CLIENT ROLE and require user to belong to at least one group.
        - Uses `client_id` if provided; otherwise falls back to `config.CLIENT_ID`.
        - 401 if client_id cannot be resolved (caller/config error)
        - 403 if user lacks the required client role or is not in any group
        - 500 with error_id for unexpected/system failures
        """
        try:
            if client_id is None or client_id == "":
                client_id = getattr(config, "CLIENT_ID", None)
                if not client_id:
                    # Caller/config error → 401 as an auth precondition failure
                    raise HTTPException(
                        status_code=HTTP_401_UNAUTHORIZED,
                        detail="Client id required for client role check",
                    )
        except HTTPException:
            raise
        except Exception as e:
            err_id = _log_exc("decorator.check_user_access:resolve_client_id", e)
            raise HTTPException(
                status_code=HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Access check failed due to a system error (error_id={err_id}).",
            )

        def _decorator(func: Callable):
            def _resolve_user(args, kwargs) -> Dict[str, Any]:
                try:
                    user = kwargs.get("user")
                    if isinstance(user, dict):
                        return user
                    for a in args:
                        if isinstance(a, dict) and "client_roles" in a:
                            return a
                    raise HTTPException(
                        status_code=HTTP_401_UNAUTHORIZED,
                        detail="User context missing"
                    )
                except HTTPException:
                    raise
                except Exception as e:
                    err_id = _log_exc("decorator._resolve_user", e)
                    raise HTTPException(
                        status_code=HTTP_500_INTERNAL_SERVER_ERROR,
                        detail=f"Unable to resolve user context (error_id={err_id}).",
                    )

            def _run_check(user: Dict[str, Any]):
                try:
                    # 1) Required client role
                    cr = (user.get("client_roles") or {}).get(client_id) or []
                    if required_role not in cr:
                        raise HTTPException(
                            status_code=HTTP_403_FORBIDDEN,
                            detail="Insufficient client role",
                        )

                    # 2) Must belong to at least one group
                    groups = user.get("groups") or []
                    if not groups:
                        raise HTTPException(
                            status_code=HTTP_403_FORBIDDEN,
                            detail="User must belong to at least one group",
                        )

                except HTTPException:
                    raise
                except Exception as e:
                    err_id = _log_exc("decorator._run_check", e)
                    raise HTTPException(
                        status_code=HTTP_500_INTERNAL_SERVER_ERROR,
                        detail=f"Access check failed due to a system error (error_id={err_id}).",
                    )

            is_async = inspect.iscoroutinefunction(func)

            @wraps(func)
            async def async_wrapper(*args, **kwargs):
                user = _resolve_user(args, kwargs)
                _run_check(user)
                return await func(*args, **kwargs)

            @wraps(func)
            def sync_wrapper(*args, **kwargs):
                user = _resolve_user(args, kwargs)
                _run_check(user)
                return func(*args, **kwargs)

            return async_wrapper if is_async else sync_wrapper

        return _decorator
    

