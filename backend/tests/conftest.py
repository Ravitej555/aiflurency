"""
ThreatLens AI — Test Fixtures & Configuration

Provides:
- In-memory async SQLite DB for fast, isolated tests
- FastAPI test client (httpx AsyncClient)
- Factories for User and ThreatEvent objects
"""

import asyncio
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.database import Base, get_db
from app.core.security import get_password_hash, create_access_token
from app.main import app
from app.models.user import User
from app.models.threat import ThreatEvent, ThreatSeverity, ThreatStatus

# ── Use SQLite for tests (no PostgreSQL required) ────────────────────────────
TEST_DATABASE_URL = "sqlite+aiosqlite:///./test.db"

test_engine = create_async_engine(TEST_DATABASE_URL, echo=False)
TestSessionLocal = async_sessionmaker(bind=test_engine, class_=AsyncSession, expire_on_commit=False)


@pytest.fixture(scope="session")
def event_loop():
    """Single event loop for the entire test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="function", autouse=True)
async def setup_db():
    """Create all tables before each test, drop after."""
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture
async def db_session() -> AsyncSession:
    async with TestSessionLocal() as session:
        yield session


@pytest_asyncio.fixture
async def client(db_session: AsyncSession) -> AsyncClient:
    """Override DB dependency to use the test session."""
    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        yield client
    app.dependency_overrides.clear()


# ── Test Data Factories ──────────────────────────────────────────────────────

async def create_test_user(
    db: AsyncSession,
    email: str = "analyst@threatlens.ai",
    username: str = "analyst",
    password: str = "SecurePass123",
    is_admin: bool = False,
) -> User:
    user = User(
        email=email,
        username=username,
        full_name="Test Analyst",
        hashed_password=get_password_hash(password),
        is_admin=is_admin,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


async def create_test_threat(
    db: AsyncSession,
    reported_by_id: int,
    severity: ThreatSeverity = ThreatSeverity.HIGH,
) -> ThreatEvent:
    threat = ThreatEvent(
        title="Suspicious lateral movement detected",
        description="Multiple failed login attempts from internal subnet",
        severity=severity,
        threat_type="lateral_movement",
        source_ip="192.168.1.100",
        affected_asset="dc-server-01",
        reported_by_id=reported_by_id,
    )
    db.add(threat)
    await db.commit()
    await db.refresh(threat)
    return threat


def auth_headers(user: User) -> dict:
    """Return Authorization header dict for a given user."""
    token = create_access_token(user.id)
    return {"Authorization": f"Bearer {token}"}
