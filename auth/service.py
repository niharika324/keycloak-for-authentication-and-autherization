from typing import Dict, Any, List
from fastapi import HTTPException
from starlette.status import HTTP_401_UNAUTHORIZED, HTTP_500_INTERNAL_SERVER_ERROR
from keycloak import KeycloakOpenID
import config
import uuid
import logging, traceback

logger = logging.getLogger("uvicorn.error")

def _log_exc(context: str, exc: Exception) -> str:
    """
    Log unexpected exceptions with a unique error ID and return that ID.
    """
    err_id = str(uuid.uuid4())
    logger.error("[%s] System exception %s: %r\n%s", context, err_id, exc, traceback.format_exc())
    return err_id


class AuthService:
    """
    Holds a single KeycloakOpenID client instance and exposes instance methods.
    """
    def __init__(self):
        try:
            self._openid = KeycloakOpenID(
                server_url=config.KC_BASE,
                realm_name=config.REALM,
                client_id=config.CLIENT_ID,
                client_secret_key=(config.CLIENT_SECRET or None),
            )
        except HTTPException:
            raise
        except Exception as e:
            err_id = _log_exc("service.__init__", e)
            raise HTTPException(
                status_code=HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Auth service initialization failed (error_id={err_id}).",
            )

    # --- Token APIs ---
    def login_password(self, username: str, password: str) -> Dict[str, Any]:
        try:
            return self._openid.token(username=username, password=password)
        except HTTPException:
            raise
        except Exception as e:
            # Treat failures here as invalid credentials unless you want to inspect the exception type.
            # Controllers also wrap these; duplication is fine and safe.
            # If you prefer, convert to 500 and let controller map to 401.
            err_id = _log_exc("service.login_password", e)
            raise HTTPException(
                status_code=HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials",
            )

    def refresh_tokens(self, refresh_token: str) -> Dict[str, Any]:
        try:
            return self._openid.refresh_token(refresh_token)
        except HTTPException:
            raise
        except Exception as e:
            err_id = _log_exc("service.refresh_tokens", e)
            # Most refresh failures are auth-related (expired/invalid refresh token)
            raise HTTPException(
                status_code=HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired refresh token",
            )

    def logout(self, refresh_token: str) -> None:
        try:
            self._openid.logout(refresh_token)
        except HTTPException:
            raise
        except Exception as e:
            err_id = _log_exc("service.logout", e)
            # Logout failures are rarely fatal to the client; surface as 500 with error_id.
            raise HTTPException(
                status_code=HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Logout failed due to a system error (error_id={err_id}).",
            )

    def introspect(self, token: str) -> Dict[str, Any]:
        try:
            data = self._openid.introspect(token)
            # If the endpoint returns falsy/None, normalize to 401
            if not data or not isinstance(data, dict) or not data.get("active", False):
                raise HTTPException(
                    status_code=HTTP_401_UNAUTHORIZED,
                    detail="Invalid or expired token",
                )
            return data
        except HTTPException:
            raise
        except Exception as e:
            err_id = _log_exc("service.introspect", e)
            raise HTTPException(
                status_code=HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Token introspection failed due to a system error (error_id={err_id}).",
            )
        
    def decode_token(self, token: str, validate: bool = True) -> Dict[str, Any]:
        """
        Wrapper over KeycloakOpenID.decode_token.
        - validate=True: full validation (sig/aud/exp). Raises on invalid/expired.
        - validate=False: parse-only; lets us read 'exp' even if expired.
        """
        try:
            return self._openid.decode_token(token, validate=validate)
        except HTTPException:
            raise
        except Exception as e:
            err_id = _log_exc(f"service.decode_token.validate_{validate}", e)
            # For middleware purposes, surface as 401 with a concise message.
            # (We keep details in logs via error_id.)
            raise HTTPException(
                status_code=HTTP_401_UNAUTHORIZED,
                detail=f"Invalid token (error_id={err_id})." if validate
                       else f"Could not read token claims (error_id={err_id})."
            )        


    # --- Helpers ---
    def build_user_context_from_token(self, token: str) -> Dict[str, Any]:
        """
        Build a user dict (user_id, username, email, name, groups, realm_roles, client_roles, raw_claims)
        from a valid access token by introspecting and reading claims.
        """
        try:
            info = self.introspect(token) or {}

            # Groups
            groups: List[str] = []
            raw_groups = info.get("groups")
            if isinstance(raw_groups, list):
                groups = [g for g in raw_groups if isinstance(g, str)]

            # Realm roles
            realm_roles: List[str] = []
            realm_access = info.get("realm_access")
            if isinstance(realm_access, dict):
                rr = realm_access.get("roles")
                if isinstance(rr, list):
                    realm_roles = [r for r in rr if isinstance(r, str)]

            # Client roles
            client_roles: Dict[str, List[str]] = {}
            resource_access = info.get("resource_access")
            if isinstance(resource_access, dict):
                for client, data in resource_access.items():
                    roles = data.get("roles") if isinstance(data, dict) else None
                    if isinstance(roles, list):
                        client_roles[client] = [r for r in roles if isinstance(r, str)]

            return {
                "user_id": info.get("sub"),
                "username": info.get("preferred_username") or info.get("email"),
                "email": info.get("email"),
                "name": info.get("name"),
                "groups": groups,
                "realm_roles": realm_roles,
                "client_roles": client_roles,
                "raw_claims": info,
            }

        except HTTPException:
            raise
        except Exception as e:
            err_id = _log_exc("service.build_user_context_from_token", e)
            raise HTTPException(
                status_code=HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to build user context due to a system error (error_id={err_id}).",
            )
        

