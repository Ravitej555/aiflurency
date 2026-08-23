"""
ThreatLens AI — Database Engine & Session Factory

Provides:
- Async SQLAlchemy engine (asyncpg driver)
- Session factory with connection pooling
- `get_db` FastAPI dependency for injecting DB sessions into route handlers
- Declarative Base for all ORM models
"""

from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.core.config import settings


# ── Declarative Base ─────────────────────────────────────────────────────────
class Base(DeclarativeBase):
    """All SQLAlchemy ORM models inherit from this base."""
    pass


# ── Async Engine ─────────────────────────────────────────────────────────────
# Connection pool tuned for Fargate tasks:
#   pool_size     — max persistent connections per worker
#   max_overflow  — additional burst connections
#   pool_pre_ping — validates connections before use (handles RDS failovers)
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,          # Log SQL statements in debug mode only
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,
    pool_recycle=3600,            # Recycle connections after 1 hour
)

# ── Session Factory ──────────────────────────────────────────────────────────
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,       # Keep objects accessible after commit
    autoflush=False,
    autocommit=False,
)


# ── FastAPI Dependency ───────────────────────────────────────────────────────
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Yield an async database session for each request.

    The session is automatically closed after the request completes.
    Transactions are NOT auto-committed — routers must call `await db.commit()`.
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
