"""

Rate limiting tests temporarily re-enable rate limiting
by unsetting the TESTING env var for the duration of the test.
"""
import os
import uuid
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.main import app
from tests.conftest import db  # reuse db fixture


@pytest_asyncio.fixture
async def rate_limit_client(db: AsyncSession):
    """Client with real rate limiting enabled."""
    from app.db import redis as redis_module
    await redis_module.init_redis_pool()

    # Re-enable rate limiting for these tests
    os.environ.pop("TESTING", None)

    async def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as ac:
        yield ac

    # Restore TESTING=true for other tests
    os.environ["TESTING"] = "true"
    app.dependency_overrides.clear()
    await redis_module.close_redis_pool()


class TestLoginRateLimit:

    async def test_login_rate_limit_enforced(
        self, rate_limit_client: AsyncClient
    ):
        """Login is blocked after 5 failed attempts."""
        from app.db.redis import get_redis
        redis = get_redis()
        await redis.delete("rate:login:testclient")

        responses = []
        for _ in range(7):
            resp = await rate_limit_client.post(
                "/api/v1/auth/login",
                json={"email": "ghost@test.com", "password": "WrongPass1!"},
            )
            responses.append(resp.status_code)

        assert 429 in responses

    async def test_rate_limit_response_format(
        self, rate_limit_client: AsyncClient
    ):
        """429 response has correct body and headers."""
        from app.db.redis import get_redis
        redis = get_redis()
        await redis.delete("rate:login:testclient")

        response = None
        for _ in range(7):
            response = await rate_limit_client.post(
                "/api/v1/auth/login",
                json={"email": "ghost@test.com", "password": "WrongPass1!"},
            )
            if response.status_code == 429:
                break

        assert response is not None
        assert response.status_code == 429
        assert response.json()["error_code"] == "SYS_RATE_LIMIT_EXCEEDED"
        assert "Retry-After" in response.headers
        assert "X-RateLimit-Limit" in response.headers


class TestRegistrationRateLimit:

    async def test_register_rate_limit_enforced(
        self, rate_limit_client: AsyncClient
    ):
        """Registration is blocked after 3 attempts."""
        from app.db.redis import get_redis
        redis = get_redis()
        await redis.delete("rate:register:testclient")

        responses = []
        for i in range(5):
            resp = await rate_limit_client.post(
                "/api/v1/auth/register",
                json={
                    "email": f"rl_{uuid.uuid4().hex[:6]}@test.com",
                    "password": "StrongPass123!",
                    "full_name": "Test",
                },
            )
            responses.append(resp.status_code)

        assert 429 in responses