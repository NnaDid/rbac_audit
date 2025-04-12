from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, DateTime, Text
from sqlalchemy.orm import relationship
from datetime import datetime
from .database import Base


class User(Base):
    __tablename__ = "users"
    id              = Column(Integer, primary_key=True, index=True)
    username        = Column(String(50), unique=True, index=True)
    email           = Column(String(100), unique=True)
    phone           = Column(String(20))
    hashed_password = Column(String(128))
    mfa_enabled     = Column(Boolean, default=False)
    role            = Column(String(20), default="user")

    logs = relationship("AuditLog", back_populates="user")


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id              = Column(Integer, primary_key=True, index=True)
    user_id         = Column(Integer, ForeignKey("users.id"))
    action_type     = Column(String(50))
    action_detail   = Column(Text)
    ip_address      = Column(String(45))
    timestamp       = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="logs")
