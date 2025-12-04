"""
认证和授权模块
"""
from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status, Header, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, func
from sqlalchemy.orm import selectinload

from database import get_db
from models import User, APIKey, DailyUsage
from config import get_settings

settings = get_settings()

# 密码加密上下文
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """验证密码"""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """获取密码哈希"""
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """创建访问令牌"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


async def get_user_by_username(db: AsyncSession, username: str) -> Optional[User]:
    """通过用户名获取用户"""
    result = await db.execute(select(User).where(User.username == username))
    return result.scalar_one_or_none()


async def get_user_by_email(db: AsyncSession, email: str) -> Optional[User]:
    """通过邮箱获取用户"""
    result = await db.execute(select(User).where(User.email == email))
    return result.scalar_one_or_none()


async def authenticate_user(db: AsyncSession, username: str, password: str) -> Optional[User]:
    """认证用户"""
    user = await get_user_by_username(db, username)
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user


async def get_current_user(
    token: Optional[str] = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
) -> Optional[User]:
    """获取当前用户（从 JWT Token）"""
    if not token:
        return None
    
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            return None
    except JWTError:
        return None
    
    user = await get_user_by_username(db, username)
    if user is None or not user.is_active:
        return None
    
    return user


async def get_current_active_user(
    current_user: Optional[User] = Depends(get_current_user)
) -> User:
    """获取当前活跃用户（必须登录）"""
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="未登录或登录已过期",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="用户已被禁用"
        )
    return current_user


async def get_current_admin_user(
    current_user: User = Depends(get_current_active_user)
) -> User:
    """获取当前管理员用户"""
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="需要管理员权限"
        )
    return current_user


async def get_api_key(
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    api_key: Optional[str] = Header(None),
    db: AsyncSession = Depends(get_db)
) -> Optional[APIKey]:
    """从请求头获取 API Key"""
    key = x_api_key or api_key
    if not key:
        return None
    
    result = await db.execute(
        select(APIKey)
        .options(selectinload(APIKey.user))
        .where(APIKey.key == key)
    )
    api_key_obj = result.scalar_one_or_none()
    
    if not api_key_obj:
        return None
    
    # 检查是否有效
    if not api_key_obj.is_active:
        return None
    
    # 检查是否过期
    if api_key_obj.expires_at and api_key_obj.expires_at < datetime.utcnow():
        return None
    
    # 检查用户是否有效
    if not api_key_obj.user.is_active:
        return None
    
    return api_key_obj


async def check_rate_limit(
    api_key: APIKey,
    db: AsyncSession
) -> tuple[bool, str]:
    """
    检查 API Key 的速率限制
    返回: (是否允许, 错误信息)
    """
    now = datetime.utcnow()
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)
    
    # 检查每日限制
    result = await db.execute(
        select(DailyUsage).where(
            and_(
                DailyUsage.api_key_id == api_key.id,
                DailyUsage.date == today
            )
        )
    )
    daily_usage = result.scalar_one_or_none()
    
    if daily_usage and daily_usage.request_count >= api_key.daily_limit:
        return False, f"已达到每日请求限制 ({api_key.daily_limit} 次/天)"
    
    return True, ""


async def record_usage(
    api_key: APIKey,
    db: AsyncSession
):
    """记录 API 使用"""
    now = datetime.utcnow()
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)
    
    # 更新每日统计
    result = await db.execute(
        select(DailyUsage).where(
            and_(
                DailyUsage.api_key_id == api_key.id,
                DailyUsage.date == today
            )
        )
    )
    daily_usage = result.scalar_one_or_none()
    
    if daily_usage:
        daily_usage.request_count += 1
    else:
        daily_usage = DailyUsage(
            api_key_id=api_key.id,
            date=today,
            request_count=1
        )
        db.add(daily_usage)
    
    # 更新 API Key 统计
    api_key.total_requests += 1
    api_key.last_used_at = now
    
    await db.commit()


async def require_api_key(
    request: Request,
    api_key: Optional[APIKey] = Depends(get_api_key),
    db: AsyncSession = Depends(get_db)
) -> APIKey:
    """要求有效的 API Key（用于 API 端点）"""
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="缺少有效的 API Key，请在请求头中添加 X-API-Key"
        )
    
    # 检查速率限制
    allowed, error_msg = await check_rate_limit(api_key, db)
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=error_msg
        )
    
    return api_key


async def optional_api_key(
    api_key: Optional[APIKey] = Depends(get_api_key),
) -> Optional[APIKey]:
    """可选的 API Key（用于公开端点，有 Key 则记录使用）"""
    return api_key


async def create_admin_user(db: AsyncSession):
    """创建默认管理员用户（如果不存在）"""
    admin = await get_user_by_username(db, settings.ADMIN_USERNAME)
    if not admin:
        admin = User(
            username=settings.ADMIN_USERNAME,
            email=settings.ADMIN_EMAIL,
            hashed_password=get_password_hash(settings.ADMIN_PASSWORD),
            is_active=True,
            is_admin=True
        )
        db.add(admin)
        await db.commit()
        print(f"✅ 已创建管理员账户: {settings.ADMIN_USERNAME}")
    return admin

