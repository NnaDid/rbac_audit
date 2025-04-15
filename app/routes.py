from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordRequestForm

from .database import get_db
from . import schema, crud, models
from .helpers import jwt, hashing, logger, dependencies

from typing import List



router = APIRouter()
# ======================= AUTH ROUTES ============================
@router.post("/login", response_model=schema.Token)
def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db) ):
    user        = crud.get_user_by_username(db, form_data.username)
    client_ip   = request.client.host

    if not user or not hashing.verify_password(form_data.password, user.hashed_password):
        logger.log_event("FAILED_LOGIN", form_data.username, f"Invalid credentials from IP {client_ip}")
        crud.create_log(db, user.id if user else None, "FAILED_LOGIN", f"Invalid credentials from IP {client_ip}",client_ip)
        raise HTTPException(status_code=400, detail="Invalid credentials")

    token = jwt.create_access_token(data={"sub": user.username, "role": user.role})
    logger.log_event("LOGIN_SUCCESS", user.username, f"Login from IP {client_ip}")
    crud.create_log(db, user.id, "LOGIN_SUCCESS", f"Login from IP {client_ip}",client_ip)
    
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "phone": user.phone,
            "role": user.role,
            "mfa": user.mfa_enabled
        }
    }

# ======================= USER ROUTES ============================
@router.get("/user/profile", response_model=schema.UserOneOut)
def get_user_profile(current_user: models.User = Depends(dependencies.get_current_user)):
    return current_user

@router.post("/user/update-profile")
def update_profile(request: Request, profile_data: schema.UserUpdate, db: Session = Depends(get_db), current_user: models.User = Depends(dependencies.get_current_user)):
    updated_user = crud.update_user_profile(db, current_user.username, profile_data)
    client_ip   = request.client.host
    logger.log_event("PROFILE_UPDATED", current_user.username)
    crud.create_log(db,current_user.id,"PROFILE_UPDATED","User Profile updated successfully",client_ip )
    return {"message": "Profile updated successfully"}

@router.post("/user/create-mfa-pin")
def enable_mfa(request: Request, db: Session = Depends(get_db), current_user: models.User = Depends(dependencies.get_current_user)):
    crud.set_mfa(db, current_user.username, True)
    client_ip   = request.client.host
    logger.log_event("MFA_ENABLED", current_user.username)
    crud.create_log(db,current_user.id,"MFA_ENABLED","User MFA_ENABLED successfully",client_ip )
    return {"message": "MFA enabled successfully"}

@router.get("/user/roles")
def get_user_roles(current_user: models.User = Depends(dependencies.get_current_user)):
    return {"roles": [current_user.role]}

# ======================= ADMIN ROUTES ============================
@router.post("/admin/create-user")
def create_user(request: Request, user_data: schema.UserCreate, db: Session = Depends(get_db), current_user: models.User = Depends(dependencies.get_admin_user)):
    new_user = crud.create_user(db, user_data)
    client_ip   = request.client.host
    logger.log_event("USER_CREATED", current_user.username, f"Created user {user_data.username}")
    crud.create_log(db,current_user.id,"USER_CREATED","USER_CREATED successfully" ,client_ip)
    return {"message": "User created successfully"}

@router.get("/admin/users", response_model=List[schema.UserOut])
def get_all_users( db: Session = Depends(get_db), current_user: models.User = Depends(dependencies.get_admin_user) ):
    users = crud.get_all_users(db)
    return users

@router.post("/admin/assign-role")
def assign_role(request: Request, role_data: schema.RoleAssignment, db: Session = Depends(get_db), current_user: models.User = Depends(dependencies.get_admin_user)):
    crud.assign_role(db, role_data.username, role_data.role)
    client_ip   = request.client.host
    logger.log_event("ROLE_CHANGED", current_user.username, f"Changed role of {role_data.username} to {role_data.role}")
    crud.create_log(db,current_user.id,"ROLE_CHANGED","ROLE_CHANGED successfully",client_ip )
    return {"message": "Role assigned successfully"}

# ======================= SECURITY TEAM ROUTES ============================
@router.get("/logs", response_model=List[schema.AuditLogOut])
def get_logs(db: Session = Depends(get_db), current_user: models.User = Depends(dependencies.get_security_user)):
    logs = crud.get_logs(db)
    return logs
