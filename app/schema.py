from pydantic import BaseModel, EmailStr
from typing import Optional

class Token(BaseModel):
    access_token: str
    token_type: str
    user: object

class UserBase(BaseModel):
    username: str
    email: str
    phone: Optional[str]

class UserCreate(UserBase):
    password: str

class UserOut(UserBase):
    role: str
    mfa_enabled: bool

class UserUpdate(BaseModel):
    email: Optional[EmailStr]
    phone: Optional[str]

class RoleAssignment(BaseModel):
    username: str
    role: str

class AuditLogOut(BaseModel):
    username: str
    event_type: str
    description: Optional[str]
    timestamp: str

    class Config:
        orm_mode = True
