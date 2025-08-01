from pydantic import BaseModel
from datetime import datetime
from typing import Optional


class SessionResponse(BaseModel):
    id: str
    user: Optional[str] = None
    box: str
    end_redirect_uri: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


class SandboxTokenResponse(BaseModel):
    access_token: str
    expires_in: Optional[int] = None
    sandbox_api_url: str
