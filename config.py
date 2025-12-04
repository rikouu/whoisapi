"""
配置文件
"""
from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    """应用配置"""
    # 数据库
    DATABASE_URL: str = "sqlite+aiosqlite:///./whoisapi.db"
    # 数据库配置（MySQL）
    #DATABASE_URL: str = "mysql+aiomysql://root:123456@localhost:3306/whoisapi"
    
    # JWT
    SECRET_KEY: str = "your-secret-key-change-this-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # 管理员默认账户
    ADMIN_USERNAME: str = "admin"
    ADMIN_PASSWORD: str = "admin"
    ADMIN_EMAIL: str = "admin@example.com"
    
    # API 默认限制
    DEFAULT_RATE_LIMIT: int = 100  # 每分钟请求数
    DEFAULT_DAILY_LIMIT: int = 1000  # 每日请求数
    
    class Config:
        env_prefix = ""
        extra = "allow"


@lru_cache()
def get_settings():
    return Settings()

