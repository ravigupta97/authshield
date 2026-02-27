"""

Shared test fixtures.

KEY DESIGN DECISIONS:

1. EVENT LOOP: Each test gets its own event loop (pytest-asyncio default
   in 'auto' mode). Redis connections must be created WITHIN each test's
   loop — not shared across tests. We reinitialize Redis per test.

2. RATE LIMITING: Tests call rate-limited endpoints repeatedly.
   We bypass rate limiting in tests by overriding the RateLimiter
   dependency to a no-op. This tests business logic, not rate limiting
   (rate limiting has its own dedicated test file).

3. DATABASE ISOLATION: Each test wraps DB operations in a transaction
   that rolls back after the test. The DB is never permanently modified.

4. ERROR RESPONSE SHAPE: Our custom exceptions return:
   {"status": "error", "message": "...", "error_code": "..."}
   FastAPI's built-in HTTPException returns:
   {"detail": {"status": "error", ..., "error_code": "..."}}
   Tests must account for both shapes.
"""

import asyncio
import sys
import uuid
from typing import AsyncGenerator

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

from app.config import settings
from app.db.session import get_db
from app.main import app
from app.models.role import Role

# ── Engine ────────────────────────────────────────────────────────

test_engine = create_async_engine(
    settings.database_url,
    poolclass=NullPool,   # No connection pooling — clean per test
    echo=False,
)

TestSessionLocal = sessionmaker(
    test_engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


# ── Rate Limit Bypass ─────────────────────────────────────────────
"""
class NoOpRateLimiter:
    
    Replaces RateLimiter in tests — always allows requests.
    This lets us call endpoints repeatedly without hitting limits.
    Rate limiting correctness is tested separately in test_rate_limiting.py
    using real rate limiters.
    
    def __init__(self, endpoint: str):
        self.endpoint = endpoint

    async def __call__(self, request) -> None:
        return None   # Always allow
"""

# ── Core Fixtures ─────────────────────────────────────────────────

@pytest_asyncio.fixture
async def db() -> AsyncGenerator[AsyncSession, None]:
    """
    Per-test database session with automatic rollback.
    Uses NullPool so each test gets a completely fresh connection.
    """
    async with test_engine.connect() as connection:
        await connection.begin()

        async with TestSessionLocal(bind=connection) as session:
            await _ensure_roles_exist(session)
            yield session

        await connection.rollback()


async def _ensure_roles_exist(session: AsyncSession) -> None:
    """Seed roles if missing. Safe to call multiple times."""
    from sqlalchemy import select

    for role_name in ["user", "moderator", "admin"]:
        result = await session.execute(
            select(Role).where(Role.name == role_name)
        )
        if not result.scalar_one_or_none():
            role = Role(name=role_name, description=f"{role_name} role")
            session.add(role)
    await session.commit()


@pytest_asyncio.fixture
async def client(db: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    """
    Test HTTP client with DB session overridden.
    Rate limiting is disabled via TESTING=true env var (set in root conftest.py).
    """
    from app.db import redis as redis_module

    await redis_module.init_redis_pool()

    async def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as ac:
        yield ac

    app.dependency_overrides.clear()
    await redis_module.close_redis_pool()

# ── Helper Functions ──────────────────────────────────────────────

async def create_test_user(
    client: AsyncClient,
    email: str = None,
    password: str = "TestPass123!",
    full_name: str = "Test User",
    verify: bool = True,
) -> dict:
    """Register and optionally verify a test user."""
    if email is None:
        email = f"test_{uuid.uuid4().hex[:8]}@example.com"

    response = await client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": password, "full_name": full_name},
    )
    assert response.status_code == 201, (
        f"Registration failed: {response.text}"
    )
    user_data = response.json()["data"]

    if verify:
        from app.db.redis import get_redis
        redis = get_redis()
        keys = await redis.keys("email_verify:*")
        for key in keys:
            stored_id = await redis.get(key)
            if stored_id == str(user_data["user_id"]):
                token = key.replace("email_verify:", "")
                await client.post(
                    "/api/v1/auth/verify-email",
                    json={"token": token},
                )
                break

    return {**user_data, "password": password, "email": email}


async def login_user(
    client: AsyncClient,
    email: str,
    password: str,
) -> dict:
    """Login and return token data."""
    response = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
    )
    assert response.status_code == 200, f"Login failed: {response.text}"
    return response.json()["data"]


def auth_header(token: str) -> dict:
    """Build Authorization header."""
    return {"Authorization": f"Bearer {token}"}


def get_error_code(response) -> str:
    """
    Extract error_code from either response shape:
    - Our custom exceptions: {"error_code": "..."}
    - FastAPI HTTPException: {"detail": {"error_code": "..."}}
    """
    body = response.json()
    if "error_code" in body:
        return body["error_code"]
    detail = body.get("detail")
    if isinstance(detail, dict):
        return detail.get("error_code", "")
    return ""


# ── Reusable User Fixtures ────────────────────────────────────────

@pytest_asyncio.fixture
async def regular_user(client: AsyncClient) -> dict:
    """Verified regular user with fresh tokens."""
    user = await create_test_user(client)
    tokens = await login_user(client, user["email"], user["password"])
    return {**user, **tokens}


@pytest_asyncio.fixture
async def admin_user(client: AsyncClient, db: AsyncSession) -> dict:
    """Verified user with admin role."""
    from sqlalchemy import select
    from app.models.user import User
    from app.models.role import Role as RoleModel

    user = await create_test_user(client)

    result = await db.execute(
        select(User).where(User.email == user["email"])
    )
    db_user = result.scalar_one()

    admin_role_result = await db.execute(
        select(RoleModel).where(RoleModel.name == "admin")
    )
    admin_role = admin_role_result.scalar_one()
    db_user.roles.append(admin_role)
    await db.commit()
    await db.refresh(db_user)

    tokens = await login_user(client, user["email"], user["password"])
    return {**user, **tokens}