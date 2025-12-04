"""
数据库模型
"""
from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text, BigInteger
from sqlalchemy.orm import relationship
from database import Base
import secrets


class User(Base):
    """用户表"""
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # 关联
    api_keys = relationship("APIKey", back_populates="user", cascade="all, delete-orphan")


class APIKey(Base):
    """API Key 表"""
    __tablename__ = "api_keys"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    key = Column(String(64), unique=True, index=True, nullable=False)
    name = Column(String(100), nullable=False)  # Key 名称/描述
    is_active = Column(Boolean, default=True)
    
    # 限制设置
    rate_limit = Column(Integer, default=100)  # 每分钟请求数限制
    daily_limit = Column(Integer, default=1000)  # 每日请求数限制
    
    # 有效期
    expires_at = Column(DateTime, nullable=True)  # null 表示永不过期
    
    # 统计
    total_requests = Column(BigInteger, default=0)
    last_used_at = Column(DateTime, nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # 关联
    user = relationship("User", back_populates="api_keys")
    usage_logs = relationship("UsageLog", back_populates="api_key", cascade="all, delete-orphan")
    
    @staticmethod
    def generate_key():
        """生成随机 API Key"""
        return secrets.token_hex(32)


class UsageLog(Base):
    """API 使用日志表"""
    __tablename__ = "usage_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    api_key_id = Column(Integer, ForeignKey("api_keys.id", ondelete="CASCADE"), nullable=False)
    
    # 请求信息
    endpoint = Column(String(100), nullable=False)  # API 端点
    domain = Column(String(255), nullable=True)  # 查询的域名
    query_type = Column(String(20), nullable=False)  # whois/dns/lookup
    
    # 响应信息
    status_code = Column(Integer, nullable=False)
    response_time = Column(Integer, nullable=True)  # 响应时间（毫秒）
    
    # 客户端信息
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    # 关联
    api_key = relationship("APIKey", back_populates="usage_logs")


class DailyUsage(Base):
    """每日使用统计表（用于快速统计）"""
    __tablename__ = "daily_usage"
    
    id = Column(Integer, primary_key=True, index=True)
    api_key_id = Column(Integer, ForeignKey("api_keys.id", ondelete="CASCADE"), nullable=False)
    date = Column(DateTime, nullable=False, index=True)  # 日期（只保留年月日）
    request_count = Column(Integer, default=0)
    
    class Meta:
        unique_together = ['api_key_id', 'date']

