from sqlalchemy.orm import Session
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

def get_logs(db: Session):
    return db.query(models.AuditLog).all()

def create_log(db: Session, uderid: int, event_type: str, description: str = None):
    log = models.AuditLog(user_id=uderid, action_type=event_type, action_detail=description,ip_address="192.23.34.8")
    db.add(log)
    db.commit()
