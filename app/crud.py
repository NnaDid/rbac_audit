from sqlalchemy.orm import Session
from fastapi import Request
from . import models, schema
from .helpers import hashing

def get_user_by_username(db: Session, username: str):
    return db.query(models.User).filter(models.User.username == username).first()

def create_user(db: Session, user: schema.UserCreate):
    hashed_pw = hashing.hash_password(user.password)
    db_user = models.User(
        username=user.username,
        email=user.email,
        phone=user.phone,
        hashed_password=hashed_pw,
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def update_user_profile(db: Session, username: str, profile_data: schema.UserUpdate):
    user = get_user_by_username(db, username)
    if profile_data.email:
        user.email = profile_data.email
    if profile_data.phone:
        user.phone = profile_data.phone
    db.commit()
    db.refresh(user)
    return user

def set_mfa(db: Session, username: str, enable: bool):
    user = get_user_by_username(db, username)
    user.mfa_enabled = enable
    db.commit()
    return user

def assign_role(db: Session, username: str, role: str):
    user = get_user_by_username(db, username)
    user.role = role
    db.commit()
    return user

# def get_logs(db: Session):
#     return db.query(models.AuditLog).all()
def get_logs(db: Session):
    logs = db.query(models.AuditLog).all()

    result = []
    for log in logs:
        result.append(schema.AuditLogOut(
            id=log.id,
            user_id=log.user_id,
            username=log.user.username,  # coming from relationship
            event_type=log.action_type,
            description=log.action_detail,
            ip_address=log.ip_address,
            timestamp=log.timestamp.isoformat() 
        ))

    return result

def get_all_users(db: Session):
    return db.query(models.User).all()

def create_log(db: Session, uderid: int, event_type: str, description: str = None, ip:str = None):
    log = models.AuditLog(user_id=uderid, action_type=event_type, action_detail=description,ip_address=ip)
    db.add(log)
    db.commit()
