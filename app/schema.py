from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime

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

class UserOneOut(UserBase):
    role: str
    mfa_enabled: bool

class UserOut(BaseModel):
    id: int
    username: str
    email: Optional[str]
    phone: Optional[str]
    role: str
    mfa_enabled: bool

    class Config:
        orm_mode = True
        
class UserUpdate(BaseModel):
    email: Optional[EmailStr]
    phone: Optional[str]

class RoleAssignment(BaseModel):
    username: str
    role: str

class AuditLogOut(BaseModel):
    id: int
    user_id: int
    username: str
    event_type: str      
    description: str   
    ip_address: str
    timestamp: str    

    class Config:
        orm_mode = True
