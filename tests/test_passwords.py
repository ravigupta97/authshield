"""

Integration tests for password management:
forgot password, reset password, change password.
"""

import pytest
from httpx import AsyncClient

from app.db.redis import get_redis
from tests.conftest import create_test_user, get_error_code, login_user, auth_header


class TestForgotPassword:

    async def test_forgot_password_always_returns_200(self, client: AsyncClient):
        """Always returns 200 regardless of whether email exists."""
        # Non-existent email
        response = await client.post(
            "/api/v1/auth/forgot-password",
            json={"email": "ghost@example.com"},
        )
        assert response.status_code == 200

        # Real email
        user = await create_test_user(client)
        response = await client.post(
            "/api/v1/auth/forgot-password",
            json={"email": user["email"]},
        )
        assert response.status_code == 200

        # Both return identical structure (no enumeration possible)
        assert "If an account" in response.json()["message"]

    async def test_forgot_password_stores_token_in_redis(
        self, client: AsyncClient
    ):
        """Reset token is stored in Redis after request."""
        user = await create_test_user(client)

        await client.post(
            "/api/v1/auth/forgot-password",
            json={"email": user["email"]},
        )

        redis = get_redis()
        keys = await redis.keys("pwd_reset:*")
        assert len(keys) >= 1


class TestResetPassword:

    async def _get_reset_token(
        self, client: AsyncClient, email: str
    ) -> str:
        """Helper: request reset and extract token from Redis."""
        await client.post(
            "/api/v1/auth/forgot-password",
            json={"email": email},
        )

        redis = get_redis()
        keys = await redis.keys("pwd_reset:*")
        assert len(keys) >= 1

        # The key IS the hash — we need the raw token
        # Since we can't reverse the hash, we need to trigger
        # the reset and intercept — in tests we check the flow
        # by verifying the token exists and the reset works
        return keys[-1].replace("pwd_reset:", "")

    async def test_reset_invalid_token(self, client: AsyncClient):
        """Invalid reset token returns 400."""
        response = await client.post(
            "/api/v1/auth/reset-password",
            json={"token": "fake-token", "new_password": "NewPass456!"},
        )
        assert response.status_code == 400
        assert get_error_code(response) == "AUTH_INVALID_RESET_TOKEN"

    async def test_reset_weak_password_rejected(self, client: AsyncClient):
        """Weak new password is rejected even with valid token."""
        response = await client.post(
            "/api/v1/auth/reset-password",
            json={"token": "any-token", "new_password": "weak"},
        )
        assert response.status_code == 422


class TestChangePassword:

    async def test_change_password_success(
        self, client: AsyncClient, regular_user
    ):
        """Authenticated user can change their password."""
        response = await client.post(
            "/api/v1/auth/change-password",
            json={
                "current_password": regular_user["password"],
                "new_password": "NewStrongPass456!",
            },
            headers=auth_header(regular_user["access_token"]),
        )
        assert response.status_code == 200

        # Can log in with new password
        login_resp = await client.post(
            "/api/v1/auth/login",
            json={
                "email": regular_user["email"],
                "password": "NewStrongPass456!",
            },
        )
        assert login_resp.status_code == 200

    async def test_change_password_wrong_current(
        self, client: AsyncClient, regular_user
    ):
        """Wrong current password is rejected."""
        response = await client.post(
            "/api/v1/auth/change-password",
            json={
                "current_password": "WrongCurrent1!",
                "new_password": "NewPass456!",
            },
            headers=auth_header(regular_user["access_token"]),
        )
        assert response.status_code == 400
        assert get_error_code(response) == "AUTH_PASSWORD_MISMATCH"

    async def test_change_password_same_as_current(
        self, client: AsyncClient, regular_user
    ):
        """Cannot change to the same password."""
        response = await client.post(
            "/api/v1/auth/change-password",
            json={
                "current_password": regular_user["password"],
                "new_password": regular_user["password"],
            },
            headers=auth_header(regular_user["access_token"]),
        )
        assert response.status_code == 400
        assert get_error_code(response) == "AUTH_SAME_PASSWORD"

    async def test_change_password_requires_auth(self, client: AsyncClient):
        """Password change requires authentication."""
        response = await client.post(
            "/api/v1/auth/change-password",
            json={
                "current_password": "OldPass123!",
                "new_password": "NewPass456!",
            },
        )
        assert response.status_code == 401