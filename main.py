from fastapi import FastAPI, Depends, HTTPException, status
from starlette.requests import Request
from typing import Dict, Any
import logging, traceback, uuid

from models import LoginRequest, TokenResponse, UserInfo, AgentCreate, Agent
from auth.decorator import AuthDecorator
from auth.controller import AuthController
from auth.service import AuthService
from auth.middleware import AuthMiddleware

app = FastAPI(title="Keycloak Auth API", version="1.0.0")

app.add_middleware(AuthMiddleware)

logger = logging.getLogger("uvicorn.error")

def _log_exc(context: str, exc: Exception) -> str:
    err_id = str(uuid.uuid4())
    logger.error("[%s] System exception %s: %r\n%s", context, err_id, exc, traceback.format_exc())
    return err_id

@app.on_event("startup")
def _startup():
    # Single service instance for the whole app
    app.state.auth_service = AuthService()

def get_service(request: Request) -> AuthService:
    return request.app.state.auth_service


@app.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, svc: AuthService = Depends(get_service)):
    """
    Authenticate and return tokens.
    """
    try:
        # Controller will raise HTTPException(401) for bad creds — let it bubble.
        return AuthController.login(payload, svc)
    except HTTPException:
        raise
    except Exception as e:
        # Unexpected failure (Keycloak down, config error, network, etc.)
        err_id = _log_exc("login", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Login failed due to a system error (error_id={err_id}).",
        )

@app.get("/me", response_model=UserInfo)
def me(user: Dict[str, Any] = Depends(AuthDecorator.get_current_user)):
    """
    Return current user profile derived from token.
    """
    try:
        # If token invalid/expired, decorator already raises 401 — let it bubble.
        return UserInfo(**user)
    except HTTPException:
        raise
    except Exception as e:
        err_id = _log_exc("me", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unable to retrieve user profile at the moment (error_id={err_id}).",
        )


@app.get("/departments", summary="List departments (groups) of the current user")
def list_departments(
    user: Dict[str, Any] = Depends(AuthDecorator.get_current_user)
) -> Dict[str, Any]:
    """
    List groups (departments) of the current user.
    """
    try:
        groups = user.get("groups", [])
        return {"groups": groups}
    except HTTPException:
        raise
    except Exception as e:
        err_id = _log_exc("list_departments", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unable to retrieve departments at the moment (error_id={err_id}).",
        )
@app.get("/roles", summary="List client roles of the current user")
def list_roles(
    user: Dict[str, Any] = Depends(AuthDecorator.get_current_user)
) -> Dict[str, Any]:
    """
    List client roles of the current user.
    """
    try:
        client_roles = user.get("client_roles", {})
        return {"client_roles": client_roles}
    except HTTPException:
        raise
    except Exception as e:
        err_id = _log_exc("list_roles", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unable to retrieve roles at the moment (error_id={err_id}).",
        )
    
@app.post("/agents", response_model=Agent)
@AuthDecorator.check_user_access("admin")  # client-role-only; defaults to config.CLIENT_ID
def create_agent(
    user: Dict[str, Any] = Depends(AuthDecorator.get_current_user),
    payload: AgentCreate = None
):
    """
    Create an agent. Requires client role 'admin'.
    """
    try:
        # Input validation specific to this endpoint
        if payload is None or not getattr(payload, "display_name", "").strip():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="display_name is required to create an agent.",
            )

        agent_name = payload.display_name.strip()
        created_by = user.get("username") or user.get("user_id") or "unknown"
        creator_email = user.get("email") or "unknown"

        return AuthController.create_agent_logic(agent_name, created_by, creator_email)

    except HTTPException:
        # Includes: 401 from token issues, 403 from role check, 400 from our validation
        raise
    except Exception as e:
        err_id = _log_exc("create_agent", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create agent due to a system error (error_id={err_id}).",
        )

