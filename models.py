from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, EmailStr

class LoginRequest(BaseModel):
    username: str = Field(..., examples=["anne"])
    password: str = Field(..., examples=["secret"])

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: Optional[str] = None
    token_type: str
    expires_in: Optional[int] = None
    scope: Optional[str] = None

class UserInfo(BaseModel):
    user_id: str
    username: Optional[str] = None
    email: Optional[str] = None
    name: Optional[str] = None
    groups: List[str] = []
    realm_roles: List[str] = []
    client_roles: Dict[str, List[str]] = {}
    raw_claims: Dict[str, Any] = {}

class AgentCreate(BaseModel):
    display_name: str

class Agent(BaseModel):
    id: str
    display_name: str
    created_by: str
