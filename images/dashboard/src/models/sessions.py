from sqlalchemy import Column, String, DateTime, Text
from database import Base
from datetime import datetime, timezone


class Sessions(Base):
    __tablename__ = "sessions"
    id = Column(String, primary_key=True, index=True)
    box = Column(String)
    user = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    end_redirect_uri = Column(String, nullable=True)
    sandbox_oauth_token = Column(Text, nullable=True)
    sandbox_token_expires_at = Column(DateTime(timezone=True), nullable=True)
