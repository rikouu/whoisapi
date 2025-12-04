"""
用户 API Key 管理路由
"""
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_

from database import get_db
from auth import get_current_active_user
from models import User, APIKey, DailyUsage
from schemas import (
    APIKeyCreate, APIKeyUpdate, APIKeyResponse, APIKeyListResponse,
    UsageStats, DailyUsageResponse, MessageResponse
)
from config import get_settings

settings = get_settings()
router = APIRouter(prefix="/api/keys", tags=["API Key"])


@router.get("", response_model=list[APIKeyListResponse])
async def list_my_api_keys(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """获取我的 API Key 列表"""
    result = await db.execute(
        select(APIKey)
        .where(APIKey.user_id == current_user.id)
        .order_by(APIKey.created_at.desc())
    )
    keys = result.scalars().all()
    
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
            created_at=k.created_at
        )
        for k in keys
    ]


@router.post("", response_model=APIKeyResponse)
async def create_api_key(
    key_data: APIKeyCreate,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """创建新的 API Key"""
    # 检查用户的 Key 数量限制（普通用户最多 5 个，管理员无限制）
    if not current_user.is_admin:
        count_result = await db.execute(
            select(func.count(APIKey.id)).where(APIKey.user_id == current_user.id)
        )
        key_count = count_result.scalar() or 0
        if key_count >= 5:
            raise HTTPException(
                status_code=400,
                detail="已达到 API Key 数量上限（最多 5 个）"
            )
    
    # 创建 API Key
    api_key = APIKey(
        user_id=current_user.id,
        key=APIKey.generate_key(),
        name=key_data.name,
        rate_limit=min(key_data.rate_limit, settings.DEFAULT_RATE_LIMIT) if not current_user.is_admin else key_data.rate_limit,
        daily_limit=min(key_data.daily_limit, settings.DEFAULT_DAILY_LIMIT) if not current_user.is_admin else key_data.daily_limit,
        expires_at=key_data.expires_at
    )
    
    db.add(api_key)
    await db.commit()
    await db.refresh(api_key)
    
    # 返回完整的 Key（只在创建时显示一次）
    return APIKeyResponse(
        id=api_key.id,
        name=api_key.name,
        key=api_key.key,  # 完整 key
        is_active=api_key.is_active,
        rate_limit=api_key.rate_limit,
        daily_limit=api_key.daily_limit,
        expires_at=api_key.expires_at,
        total_requests=api_key.total_requests,
        last_used_at=api_key.last_used_at,
        created_at=api_key.created_at,
        user_id=api_key.user_id
    )


@router.get("/{key_id}", response_model=APIKeyListResponse)
async def get_api_key(
    key_id: int,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """获取 API Key 详情"""
    result = await db.execute(
        select(APIKey).where(
            and_(APIKey.id == key_id, APIKey.user_id == current_user.id)
        )
    )
    api_key = result.scalar_one_or_none()
    
    if not api_key:
        raise HTTPException(status_code=404, detail="API Key 不存在")
    
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


@router.put("/{key_id}", response_model=APIKeyListResponse)
async def update_api_key(
    key_id: int,
    key_data: APIKeyUpdate,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """更新 API Key"""
    result = await db.execute(
        select(APIKey).where(
            and_(APIKey.id == key_id, APIKey.user_id == current_user.id)
        )
    )
    api_key = result.scalar_one_or_none()
    
    if not api_key:
        raise HTTPException(status_code=404, detail="API Key 不存在")
    
    if key_data.name is not None:
        api_key.name = key_data.name
    if key_data.is_active is not None:
        api_key.is_active = key_data.is_active
    
    # 非管理员不能超过默认限制
    if key_data.rate_limit is not None:
        api_key.rate_limit = min(key_data.rate_limit, settings.DEFAULT_RATE_LIMIT) if not current_user.is_admin else key_data.rate_limit
    if key_data.daily_limit is not None:
        api_key.daily_limit = min(key_data.daily_limit, settings.DEFAULT_DAILY_LIMIT) if not current_user.is_admin else key_data.daily_limit
    
    if key_data.expires_at is not None:
        api_key.expires_at = key_data.expires_at
    
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


@router.delete("/{key_id}", response_model=MessageResponse)
async def delete_api_key(
    key_id: int,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """删除 API Key"""
    result = await db.execute(
        select(APIKey).where(
            and_(APIKey.id == key_id, APIKey.user_id == current_user.id)
        )
    )
    api_key = result.scalar_one_or_none()
    
    if not api_key:
        raise HTTPException(status_code=404, detail="API Key 不存在")
    
    await db.delete(api_key)
    await db.commit()
    
    return MessageResponse(message="API Key 已删除")


@router.get("/{key_id}/stats", response_model=UsageStats)
async def get_api_key_stats(
    key_id: int,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """获取 API Key 使用统计"""
    result = await db.execute(
        select(APIKey).where(
            and_(APIKey.id == key_id, APIKey.user_id == current_user.id)
        )
    )
    api_key = result.scalar_one_or_none()
    
    if not api_key:
        raise HTTPException(status_code=404, detail="API Key 不存在")
    
    # 获取今日使用量
    today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    daily_result = await db.execute(
        select(DailyUsage).where(
            and_(
                DailyUsage.api_key_id == api_key.id,
                DailyUsage.date == today
            )
        )
    )
    daily_usage = daily_result.scalar_one_or_none()
    today_requests = daily_usage.request_count if daily_usage else 0
    
    return UsageStats(
        total_requests=api_key.total_requests,
        today_requests=today_requests,
        daily_limit=api_key.daily_limit,
        rate_limit=api_key.rate_limit,
        remaining_today=max(0, api_key.daily_limit - today_requests)
    )


@router.get("/{key_id}/usage", response_model=list[DailyUsageResponse])
async def get_api_key_daily_usage(
    key_id: int,
    days: int = Query(default=30, ge=1, le=90),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """获取 API Key 每日使用记录"""
    result = await db.execute(
        select(APIKey).where(
            and_(APIKey.id == key_id, APIKey.user_id == current_user.id)
        )
    )
    api_key = result.scalar_one_or_none()
    
    if not api_key:
        raise HTTPException(status_code=404, detail="API Key 不存在")
    
    # 获取最近 N 天的使用记录
    from_date = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    from_date = from_date - timedelta(days=days)
    
    usage_result = await db.execute(
        select(DailyUsage)
        .where(
            and_(
                DailyUsage.api_key_id == api_key.id,
                DailyUsage.date >= from_date
            )
        )
        .order_by(DailyUsage.date.desc())
    )
    usage_records = usage_result.scalars().all()
    
    return [
        DailyUsageResponse(
            date=u.date,
            request_count=u.request_count
        )
        for u in usage_records
    ]


from datetime import timedelta

