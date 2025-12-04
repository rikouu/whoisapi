"""
数据库连接和会话管理
"""
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base
from config import get_settings

settings = get_settings()

# 根据数据库类型配置引擎参数
engine_kwargs = {
    "echo": False,
}

# SQLite 使用 NullPool，不支持 pool_size/max_overflow
# MySQL 使用 QueuePool，需要连接池配置
if settings.DATABASE_URL.startswith("sqlite"):
    # SQLite: 不需要连接池参数
    pass
else:
    # MySQL/PostgreSQL: 使用连接池
    engine_kwargs.update({
        "pool_pre_ping": True,
        "pool_size": 10,
        "max_overflow": 20,
    })

# 创建异步引擎
engine = create_async_engine(
    settings.DATABASE_URL,
    **engine_kwargs
)

# 创建异步会话工厂
AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)

# 基类
Base = declarative_base()


async def get_db():
    """获取数据库会话"""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()


async def init_db():
    """初始化数据库表"""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

