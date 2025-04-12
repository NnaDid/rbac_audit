from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordRequestForm

from .database import get_db
from . import schema, crud, models
from .helpers import jwt, hashing, logger, dependencies

from typing import List



router = APIRouter()
# ======================= AUTH ROUTES ============================
@router.post("/login", response_model=schema.Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = crud.get_user_by_username(db, form_data.username)
    if not user or not hashing.verify_password(form_data.password, user.hashed_password):
        logger.log_event("FAILED_LOGIN", user.username, "Invalid credentials")
        crud.create_log(db,user.id,"FAILED_LOGIN","Invalid credentials")
        raise HTTPException(status_code=400, detail="Invalid credentials")

    token = jwt.create_access_token(data={"sub": user.username, "role": user.role})
    logger.log_event("LOGIN_SUCCESS", user.username)
    crud.create_log(db,user.id,"LOGIN_SUCCESS","Correct Login details")
    return {"access_token": token, "token_type": "bearer","user":{"id":user.id,"username":user.username, "email":user.email,"phone":user.phone, "role":user.role, "mfa":user.mfa_enabled}} 

# ======================= USER ROUTES ============================
@router.get("/user/profile", response_model=schema.UserOut)
def get_user_profile(current_user: models.User = Depends(dependencies.get_current_user)):
    return current_user

@router.post("/user/update-profile")
def update_profile(profile_data: schema.UserUpdate, db: Session = Depends(get_db), current_user: models.User = Depends(dependencies.get_current_user)):
    updated_user = crud.update_user_profile(db, current_user.username, profile_data)
    logger.log_event("PROFILE_UPDATED", current_user.username)
    crud.create_log(db,current_user.id,"PROFILE_UPDATED","User Profile updated successfully" )
    return {"message": "Profile updated successfully"}

@router.post("/user/create-mfa-pin")
def enable_mfa(db: Session = Depends(get_db), current_user: models.User = Depends(dependencies.get_current_user)):
    crud.set_mfa(db, current_user.username, True)
    logger.log_event("MFA_ENABLED", current_user.username)
    crud.create_log(db,current_user.id,"MFA_ENABLED","User MFA_ENABLED successfully" )
    return {"message": "MFA enabled successfully"}

@router.get("/user/roles")
def get_user_roles(current_user: models.User = Depends(dependencies.get_current_user)):
    return {"roles": [current_user.role]}

# ======================= ADMIN ROUTES ============================
@router.post("/admin/create-user")
def create_user(user_data: schema.UserCreate, db: Session = Depends(get_db), current_user: models.User = Depends(dependencies.get_admin_user)):
    new_user = crud.create_user(db, user_data)
    logger.log_event("USER_CREATED", current_user.username, f"Created user {user_data.username}")
    crud.create_log(db,current_user.id,"USER_CREATED","USER_CREATED successfully" )
    return {"message": "User created successfully"}

@router.post("/admin/assign-role")
def assign_role(role_data: schema.RoleAssignment, db: Session = Depends(get_db), current_user: models.User = Depends(dependencies.get_admin_user)):
    crud.assign_role(db, role_data.username, role_data.role)
    logger.log_event("ROLE_CHANGED", current_user.username, f"Changed role of {role_data.username} to {role_data.role}")
    crud.create_log(db,current_user.id,"ROLE_CHANGED","ROLE_CHANGED successfully" )
    return {"message": "Role assigned successfully"}

# ======================= SECURITY TEAM ROUTES ============================
@router.get("/logs", response_model=List[schema.AuditLogOut])
def get_logs(db: Session = Depends(get_db), current_user: models.User = Depends(dependencies.get_security_user)):
    logs = crud.get_logs(db)
    return logs
