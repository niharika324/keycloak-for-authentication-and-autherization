from fastapi import HTTPException
from starlette.status import HTTP_401_UNAUTHORIZED, HTTP_500_INTERNAL_SERVER_ERROR, HTTP_400_BAD_REQUEST
from typing import Dict, Any, List
from models import LoginRequest
from datetime import datetime
import uuid
import logging, traceback

from models import Agent, AgentCreate
from auth.service import AuthService

# In-memory storage for agents (example)
_AGENTS = []

# Use Uvicorn's logger so messages appear in the app logs
logger = logging.getLogger("uvicorn.error")

def _log_exc(context: str, exc: Exception) -> str:
    """
    Log unexpected exceptions with a unique error ID and return that ID.
    """
    err_id = str(uuid.uuid4())
    logger.error("[%s] System exception %s: %r\n%s", context, err_id, exc, traceback.format_exc())
    return err_id


class AuthController:
    @staticmethod
    def login(payload: LoginRequest, svc: AuthService) -> Dict[str, Any]:
        """
        Authenticates a user using username and password.
        Returns token information if successful, raises HTTPException if not.
        - 401 for invalid credentials
        - 500 with error_id for unexpected/system failures
        """
        try:
            token_dict = svc.login_password(payload.username, payload.password)

            # If your service returns None/empty on bad creds, normalize to 401 here:
            if not token_dict or "access_token" not in token_dict:
                raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

            return token_dict

        except HTTPException:
            # Bubble up known HTTP errors (e.g., explicit 401 from the service)
            raise
        except Exception as e:
            # Unexpected/system failure (Keycloak down, config, network, etc.)
            err_id = _log_exc("controller.login", e)
            raise HTTPException(
                status_code=HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Authentication failed due to a system error (error_id={err_id}).",
            )

    @staticmethod
    def create_agent_logic(agent_name: str, created_by: str, creator_email: str) -> Agent:
        """
        Creates an Agent object, appends it to the in-memory list, and returns it.
        - 400s should be thrown by the caller if input is invalid.
        - 500 with error_id for unexpected/system failures.
        """
        try:
            payload = AgentCreate(display_name=agent_name)
            agent = Agent(
                id=str(uuid.uuid4()),
                display_name=payload.display_name,
                created_by=created_by,
                creator_email=creator_email,
                created_at=datetime.utcnow()
            )
            _AGENTS.append(agent)
            return agent

        except HTTPException:
            # If caller wants to raise a specific HTTP error, allow it
            raise
        except Exception as e:
            err_id = _log_exc("controller.create_agent_logic", e)
            raise HTTPException(
                status_code=HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to create agent due to a system error (error_id={err_id}).",
            )


