"""
Pydantic 模型（请求/响应模式）
"""
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, EmailStr, Field


# ==================== 用户相关 ====================

class UserCreate(BaseModel):
    """创建用户"""
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=6)
    is_admin: bool = False


class UserUpdate(BaseModel):
    """更新用户"""
    email: Optional[EmailStr] = None
    password: Optional[str] = Field(None, min_length=6)
    is_active: Optional[bool] = None
    is_admin: Optional[bool] = None


class UserResponse(BaseModel):
    """用户响应"""
    id: int
    username: str
    email: str
    is_active: bool
    is_admin: bool
    created_at: datetime
    
    class Config:
        from_attributes = True


class UserWithStats(UserResponse):
    """带统计信息的用户响应"""
    api_key_count: int = 0
    total_requests: int = 0


# ==================== 认证相关 ====================

class Token(BaseModel):
    """Token 响应"""
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse


class LoginRequest(BaseModel):
    """登录请求"""
    username: str
    password: str


# ==================== API Key 相关 ====================

class APIKeyCreate(BaseModel):
    """创建 API Key"""
    name: str = Field(..., min_length=1, max_length=100)
    rate_limit: int = Field(default=100, ge=1, le=10000)
    daily_limit: int = Field(default=1000, ge=1, le=1000000)
    expires_at: Optional[datetime] = None


class APIKeyUpdate(BaseModel):
    """更新 API Key"""
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    rate_limit: Optional[int] = Field(None, ge=1, le=10000)
    daily_limit: Optional[int] = Field(None, ge=1, le=1000000)
    expires_at: Optional[datetime] = None
    is_active: Optional[bool] = None


class APIKeyResponse(BaseModel):
    """API Key 响应"""
    id: int
    name: str
    key: str  # 只在创建时显示完整 key
    is_active: bool
    rate_limit: int
    daily_limit: int
    expires_at: Optional[datetime]
    total_requests: int
    last_used_at: Optional[datetime]
    created_at: datetime
    user_id: int
    
    class Config:
        from_attributes = True


class APIKeyListResponse(BaseModel):
    """API Key 列表响应（隐藏完整 key）"""
    id: int
    name: str
    key_preview: str  # 只显示前8位
    is_active: bool
    rate_limit: int
    daily_limit: int
    expires_at: Optional[datetime]
    total_requests: int
    last_used_at: Optional[datetime]
    created_at: datetime
    owner_username: Optional[str] = None  # 所有者用户名（管理员列表用）
    
    class Config:
        from_attributes = True


# ==================== 使用统计相关 ====================

class UsageStats(BaseModel):
    """使用统计"""
    total_requests: int
    today_requests: int
    daily_limit: int
    rate_limit: int
    remaining_today: int


class DailyUsageResponse(BaseModel):
    """每日使用响应"""
    date: datetime
    request_count: int


class UsageLogResponse(BaseModel):
    """使用日志响应"""
    id: int
    endpoint: str
    domain: Optional[str]
    query_type: str
    status_code: int
    response_time: Optional[int]
    ip_address: Optional[str]
    created_at: datetime
    
    class Config:
        from_attributes = True


# ==================== 系统统计 ====================

class SystemStats(BaseModel):
    """系统统计"""
    total_users: int
    active_users: int
    total_api_keys: int
    active_api_keys: int
    total_requests_today: int
    total_requests_all: int


# ==================== 通用响应 ====================

class MessageResponse(BaseModel):
    """消息响应"""
    message: str
    success: bool = True


class PaginatedResponse(BaseModel):
    """分页响应"""
    items: List
    total: int
    page: int
    page_size: int
    total_pages: int

