from pydantic_settings import BaseSettings
from functools import lru_cache

class Settings(BaseSettings):
    DATABASE_URL: str
    JWT_SECRET_KEY: str
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24
    PROJECT_NAME: str = "Secure RBAC System"
    PROJECT_VERSION: str = "1.0"

    class Config:
        env_file = ".env" 

@lru_cache()
def get_settings():
    return Settings()

settings = get_settings()
