"""
管理员路由
"""
from datetime import datetime, timedelta
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, delete

from database import get_db
from auth import get_current_admin_user, get_password_hash
from models import User, APIKey, UsageLog, DailyUsage
from schemas import (
    UserCreate, UserUpdate, UserResponse, UserWithStats,
    APIKeyCreate, APIKeyUpdate, APIKeyResponse, APIKeyListResponse,
    SystemStats, MessageResponse, UsageLogResponse
)
from config import get_settings

settings = get_settings()
router = APIRouter(prefix="/api/admin", tags=["管理"])


# ==================== 用户管理 ====================

@router.get("/users", response_model=list[UserWithStats])
async def list_users(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    admin: User = Depends(get_current_admin_user),
    db: AsyncSession = Depends(get_db)
):
    """获取用户列表"""
    result = await db.execute(
        select(User)
        .order_by(User.created_at.desc())
        .offset(skip)
        .limit(limit)
    )
    users = result.scalars().all()
    
    # 获取每个用户的统计信息
    user_list = []
    for user in users:
        # 获取 API Key 数量
        key_count_result = await db.execute(
            select(func.count(APIKey.id)).where(APIKey.user_id == user.id)
        )
        api_key_count = key_count_result.scalar() or 0
        
        # 获取总请求数
        total_result = await db.execute(
            select(func.sum(APIKey.total_requests)).where(APIKey.user_id == user.id)
        )
        total_requests = total_result.scalar() or 0
        
        user_dict = UserWithStats(
            id=user.id,
            username=user.username,
            email=user.email,
            is_active=user.is_active,
            is_admin=user.is_admin,
            created_at=user.created_at,
            api_key_count=api_key_count,
            total_requests=total_requests
        )
        user_list.append(user_dict)
    
    return user_list


@router.post("/users", response_model=UserResponse)
async def create_user(
    user_data: UserCreate,
    admin: User = Depends(get_current_admin_user),
    db: AsyncSession = Depends(get_db)
):
    """创建用户（管理员）"""
    # 检查用户名
    existing = await db.execute(select(User).where(User.username == user_data.username))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="用户名已存在")
    
    # 检查邮箱
    existing = await db.execute(select(User).where(User.email == user_data.email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="邮箱已存在")
    
    user = User(
        username=user_data.username,
        email=user_data.email,
        hashed_password=get_password_hash(user_data.password),
        is_admin=user_data.is_admin
    )
    
    db.add(user)
    await db.commit()
    await db.refresh(user)
    
    return UserResponse.model_validate(user)


@router.get("/users/{user_id}", response_model=UserWithStats)
async def get_user(
    user_id: int,
    admin: User = Depends(get_current_admin_user),
    db: AsyncSession = Depends(get_db)
):
    """获取用户详情"""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    
    # 获取统计信息
    key_count_result = await db.execute(
        select(func.count(APIKey.id)).where(APIKey.user_id == user.id)
    )
    api_key_count = key_count_result.scalar() or 0
    
    total_result = await db.execute(
        select(func.sum(APIKey.total_requests)).where(APIKey.user_id == user.id)
    )
    total_requests = total_result.scalar() or 0
    
    return UserWithStats(
        id=user.id,
        username=user.username,
        email=user.email,
        is_active=user.is_active,
        is_admin=user.is_admin,
        created_at=user.created_at,
        api_key_count=api_key_count,
        total_requests=total_requests
    )


@router.put("/users/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: int,
    user_data: UserUpdate,
    admin: User = Depends(get_current_admin_user),
    db: AsyncSession = Depends(get_db)
):
    """更新用户"""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    
    # 保护 admin 用户：不能修改其管理员权限和启用状态
    is_protected_user = user.username == 'admin'
    
    if user_data.email is not None:
        existing = await db.execute(
            select(User).where(and_(User.email == user_data.email, User.id != user_id))
        )
        if existing.scalar_one_or_none():
            raise HTTPException(status_code=400, detail="邮箱已被使用")
        user.email = user_data.email
    
    if user_data.password is not None:
        user.hashed_password = get_password_hash(user_data.password)
    
    if user_data.is_active is not None:
        if is_protected_user and not user_data.is_active:
            raise HTTPException(status_code=400, detail="无法禁用 admin 用户")
        user.is_active = user_data.is_active
    
    if user_data.is_admin is not None:
        # 不能取消自己的管理员权限
        if user.id == admin.id and not user_data.is_admin:
            raise HTTPException(status_code=400, detail="不能取消自己的管理员权限")
        # 保护 admin 用户的管理员权限
        if is_protected_user and not user_data.is_admin:
            raise HTTPException(status_code=400, detail="无法取消 admin 用户的管理员权限")
        user.is_admin = user_data.is_admin
    
    await db.commit()
    await db.refresh(user)
    
    return UserResponse.model_validate(user)


@router.delete("/users/{user_id}", response_model=MessageResponse)
async def delete_user(
    user_id: int,
    admin: User = Depends(get_current_admin_user),
    db: AsyncSession = Depends(get_db)
):
    """删除用户"""
    if user_id == admin.id:
        raise HTTPException(status_code=400, detail="不能删除自己的账户")
    
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    
    # 保护 admin 用户不被删除
    if user.username == 'admin':
        raise HTTPException(status_code=400, detail="无法删除 admin 用户")
    
    await db.delete(user)
    await db.commit()
    
    return MessageResponse(message="用户已删除")


# ==================== API Key 管理（全局） ====================

@router.get("/api-keys", response_model=list[APIKeyListResponse])
async def list_all_api_keys(
    user_id: Optional[int] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    admin: User = Depends(get_current_admin_user),
    db: AsyncSession = Depends(get_db)
):
    """获取所有 API Key 列表"""
    # 使用 JOIN 获取用户名
    query = select(APIKey, User.username).join(User, APIKey.user_id == User.id).order_by(APIKey.created_at.desc())
    
    if user_id:
        query = query.where(APIKey.user_id == user_id)
    
    result = await db.execute(query.offset(skip).limit(limit))
    rows = result.all()
    
    return [
        APIKeyListResponse(
            id=k.id,
            name=k.name,
            key_preview=k.key[:8] + "...",
            is_active=k.is_active,
            rate_limit=k.rate_limit,
            daily_limit=k.daily_limit,
            expires_at=k.expires_at,
            total_requests=k.total_requests,
            last_used_at=k.last_used_at,
            created_at=k.created_at,
            owner_username=username
        )
        for k, username in rows
    ]


@router.put("/api-keys/{key_id}", response_model=APIKeyListResponse)
async def admin_update_api_key(
    key_id: int,
    key_data: APIKeyUpdate,
    admin: User = Depends(get_current_admin_user),
    db: AsyncSession = Depends(get_db)
):
    """更新 API Key（管理员）"""
    result = await db.execute(select(APIKey).where(APIKey.id == key_id))
    api_key = result.scalar_one_or_none()
    
    if not api_key:
        raise HTTPException(status_code=404, detail="API Key 不存在")
    
    if key_data.name is not None:
        api_key.name = key_data.name
    if key_data.rate_limit is not None:
        api_key.rate_limit = key_data.rate_limit
    if key_data.daily_limit is not None:
        api_key.daily_limit = key_data.daily_limit
    if key_data.expires_at is not None:
        api_key.expires_at = key_data.expires_at
    if key_data.is_active is not None:
        api_key.is_active = key_data.is_active
    
    await db.commit()
    await db.refresh(api_key)
    
    return APIKeyListResponse(
        id=api_key.id,
        name=api_key.name,
        key_preview=api_key.key[:8] + "...",
        is_active=api_key.is_active,
        rate_limit=api_key.rate_limit,
        daily_limit=api_key.daily_limit,
        expires_at=api_key.expires_at,
        total_requests=api_key.total_requests,
        last_used_at=api_key.last_used_at,
        created_at=api_key.created_at
    )


@router.delete("/api-keys/{key_id}", response_model=MessageResponse)
async def admin_delete_api_key(
    key_id: int,
    admin: User = Depends(get_current_admin_user),
    db: AsyncSession = Depends(get_db)
):
    """删除 API Key（管理员）"""
    result = await db.execute(select(APIKey).where(APIKey.id == key_id))
    api_key = result.scalar_one_or_none()
    
    if not api_key:
        raise HTTPException(status_code=404, detail="API Key 不存在")
    
    await db.delete(api_key)
    await db.commit()
    
    return MessageResponse(message="API Key 已删除")


# ==================== 系统统计 ====================

@router.get("/stats", response_model=SystemStats)
async def get_system_stats(
    admin: User = Depends(get_current_admin_user),
    db: AsyncSession = Depends(get_db)
):
    """获取系统统计"""
    # 用户统计
    total_users_result = await db.execute(select(func.count(User.id)))
    total_users = total_users_result.scalar() or 0
    
    active_users_result = await db.execute(
        select(func.count(User.id)).where(User.is_active == True)
    )
    active_users = active_users_result.scalar() or 0
    
    # API Key 统计
    total_keys_result = await db.execute(select(func.count(APIKey.id)))
    total_api_keys = total_keys_result.scalar() or 0
    
    active_keys_result = await db.execute(
        select(func.count(APIKey.id)).where(APIKey.is_active == True)
    )
    active_api_keys = active_keys_result.scalar() or 0
    
    # 请求统计
    total_all_result = await db.execute(select(func.sum(APIKey.total_requests)))
    total_requests_all = total_all_result.scalar() or 0
    
    # 今日请求
    today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    today_result = await db.execute(
        select(func.sum(DailyUsage.request_count)).where(DailyUsage.date == today)
    )
    total_requests_today = today_result.scalar() or 0
    
    return SystemStats(
        total_users=total_users,
        active_users=active_users,
        total_api_keys=total_api_keys,
        active_api_keys=active_api_keys,
        total_requests_today=total_requests_today,
        total_requests_all=total_requests_all
    )


@router.get("/usage-logs", response_model=list[UsageLogResponse])
async def get_usage_logs(
    api_key_id: Optional[int] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    admin: User = Depends(get_current_admin_user),
    db: AsyncSession = Depends(get_db)
):
    """获取使用日志"""
    query = select(UsageLog).order_by(UsageLog.created_at.desc())
    
    if api_key_id:
        query = query.where(UsageLog.api_key_id == api_key_id)
    
    result = await db.execute(query.offset(skip).limit(limit))
    logs = result.scalars().all()
    
    return [UsageLogResponse.model_validate(log) for log in logs]

