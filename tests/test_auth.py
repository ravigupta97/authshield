"""

Integration tests for the core authentication flow:
registration, email verification, login, logout, token refresh.
"""

import pytest
from httpx import AsyncClient

from app.db.redis import get_redis
from tests.conftest import create_test_user, get_error_code, login_user, auth_header


class TestRegistration:

    async def test_register_success(self, client: AsyncClient):
        """New user can register with valid data."""
        response = await client.post(
            "/api/v1/auth/register",
            json={
                "email": "newuser@example.com",
                "password": "StrongPass123!",
                "full_name": "New User",
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["status"] == "success"
        assert data["data"]["email"] == "newuser@example.com"
        assert data["data"]["is_verified"] is False  # Not verified yet

    async def test_register_duplicate_email(self, client: AsyncClient):
        """Cannot register with an already registered email."""
        await create_test_user(client, email="duplicate@example.com")

        response = await client.post(
            "/api/v1/auth/register",
            json={
                "email": "duplicate@example.com",
                "password": "StrongPass123!",
                "full_name": "Another User",
            },
        )
        assert response.status_code == 409
        assert get_error_code(response) == "AUTH_EMAIL_ALREADY_REGISTERED"

    async def test_register_weak_password(self, client: AsyncClient):
        """Weak passwords are rejected with validation errors."""
        response = await client.post(
            "/api/v1/auth/register",
            json={
                "email": "weakpass@example.com",
                "password": "weak",
                "full_name": "Test User",
            },
        )
        assert response.status_code == 422

    async def test_register_invalid_email(self, client: AsyncClient):
        """Invalid email format is rejected."""
        response = await client.post(
            "/api/v1/auth/register",
            json={
                "email": "not-an-email",
                "password": "StrongPass123!",
                "full_name": "Test User",
            },
        )
        assert response.status_code == 422

    async def test_register_assigns_user_role(self, client: AsyncClient):
        """Newly registered user gets the 'user' role automatically."""
        user = await create_test_user(client)
        tokens = await login_user(client, user["email"], user["password"])

        response = await client.get(
            "/api/v1/users/me",
            headers=auth_header(tokens["access_token"]),
        )
        assert response.status_code == 200
        assert "user" in response.json()["data"]["roles"]


class TestEmailVerification:

    async def test_login_fails_without_verification(self, client: AsyncClient):
        """Unverified users cannot log in."""
        user = await create_test_user(client, verify=False)

        response = await client.post(
            "/api/v1/auth/login",
            json={"email": user["email"], "password": user["password"]},
        )
        assert response.status_code == 403
        assert get_error_code(response) == "AUTH_EMAIL_NOT_VERIFIED"

    async def test_verify_email_success(self, client: AsyncClient):
        """User can verify their email with the correct token."""
        user = await create_test_user(client, verify=False)

        # Get token from Redis
        redis = get_redis()
        keys = await redis.keys("email_verify:*")
        token = None
        for key in keys:
            stored_id = await redis.get(key)
            if stored_id == str(user["user_id"]):
                token = key.replace("email_verify:", "")
                break

        assert token is not None, "Verification token not found in Redis"

        response = await client.post(
            "/api/v1/auth/verify-email",
            json={"token": token},
        )
        assert response.status_code == 200

        # Can now log in
        login_response = await client.post(
            "/api/v1/auth/login",
            json={"email": user["email"], "password": user["password"]},
        )
        assert login_response.status_code == 200

    async def test_verify_email_invalid_token(self, client: AsyncClient):
        """Invalid verification token returns 400."""
        response = await client.post(
            "/api/v1/auth/verify-email",
            json={"token": "totally-invalid-token"},
        )
        assert response.status_code == 400
        assert get_error_code(response) == "AUTH_INVALID_VERIFICATION_TOKEN"

    async def test_verify_email_token_single_use(self, client: AsyncClient):
        """Verification token cannot be used twice."""
        user = await create_test_user(client, verify=False)

        redis = get_redis()
        keys = await redis.keys("email_verify:*")
        token = None
        for key in keys:
            stored_id = await redis.get(key)
            if stored_id == str(user["user_id"]):
                token = key.replace("email_verify:", "")
                break

        # First use — success
        await client.post("/api/v1/auth/verify-email", json={"token": token})

        # Second use — fails
        response = await client.post(
            "/api/v1/auth/verify-email",
            json={"token": token},
        )
        assert response.status_code == 400


class TestLogin:

    async def test_login_success(self, client: AsyncClient):
        """Verified user can log in and receives tokens."""
        user = await create_test_user(client)

        response = await client.post(
            "/api/v1/auth/login",
            json={"email": user["email"], "password": user["password"]},
        )
        assert response.status_code == 200
        data = response.json()["data"]
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "Bearer"
        assert data["expires_in"] == 900  # 15 minutes

    async def test_login_wrong_password(self, client: AsyncClient):
        """Wrong password returns 401."""
        user = await create_test_user(client)

        response = await client.post(
            "/api/v1/auth/login",
            json={"email": user["email"], "password": "WrongPassword1!"},
        )
        assert response.status_code == 401
        assert get_error_code(response) == "AUTH_INVALID_CREDENTIALS"

    async def test_login_nonexistent_email(self, client: AsyncClient):
        """Non-existent email returns same 401 as wrong password."""
        response = await client.post(
            "/api/v1/auth/login",
            json={"email": "ghost@example.com", "password": "SomePass123!"},
        )
        assert response.status_code == 401
        # Same error code — doesn't reveal whether email exists
        assert get_error_code(response) == "AUTH_INVALID_CREDENTIALS"

    async def test_login_creates_session(self, client: AsyncClient, regular_user):
        """Login creates an active session record."""
        response = await client.get(
            "/api/v1/sessions",
            headers=auth_header(regular_user["access_token"]),
        )
        assert response.status_code == 200
        sessions = response.json()["data"]["sessions"]
        assert len(sessions) >= 1
        current = [s for s in sessions if s["is_current"]]
        assert len(current) == 1


class TestTokenRefresh:

    async def test_refresh_success(self, client: AsyncClient, regular_user):
        """Valid refresh token returns new token pair."""
        response = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": regular_user["refresh_token"]},
        )
        assert response.status_code == 200
        data = response.json()["data"]
        assert "access_token" in data
        assert "refresh_token" in data
        # New tokens should differ from old ones
        assert data["access_token"] != regular_user["access_token"]
        assert data["refresh_token"] != regular_user["refresh_token"]

    async def test_refresh_token_rotation(self, client: AsyncClient, regular_user):
        """Old refresh token cannot be used after rotation."""
        old_refresh = regular_user["refresh_token"]

        # Rotate
        await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": old_refresh},
        )

        # Try to use old token again
        response = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": old_refresh},
        )
        assert response.status_code == 401
        assert get_error_code(response) == "AUTH_REFRESH_TOKEN_REUSED"

    async def test_refresh_invalid_token(self, client: AsyncClient):
        """Invalid refresh token returns 401."""
        response = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": "rt_totally_fake_token"},
        )
        assert response.status_code == 401


class TestLogout:

    async def test_logout_success(self, client: AsyncClient, regular_user):
        """Logout invalidates the access token immediately."""
        token = regular_user["access_token"]
        refresh = regular_user["refresh_token"]

        # Logout
        response = await client.post(
            "/api/v1/auth/logout",
            json={"refresh_token": refresh},
            headers=auth_header(token),
        )
        assert response.status_code == 200

        # Access token is now dead
        me_response = await client.get(
            "/api/v1/users/me",
            headers=auth_header(token),
        )
        assert response.status_code == 401, f"Expected 401, got: {response.text}"
        assert get_error_code(response) == "AUTH_TOKEN_REVOKED", (
            f"Full response: {response.json()}"
        )

    async def test_logout_all_devices(self, client: AsyncClient):
        """Logout-all revokes all sessions."""
        user = await create_test_user(client)

        # Login twice (two sessions)
        tokens1 = await login_user(client, user["email"], user["password"])
        tokens2 = await login_user(client, user["email"], user["password"])

        # Logout all using session 1's token
        await client.post(
            "/api/v1/auth/logout-all",
            headers=auth_header(tokens1["access_token"]),
        )

        # Session 2's refresh token should be dead
        response = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": tokens2["refresh_token"]},
        )
        assert response.status_code == 401


class TestProtectedRoutes:

    async def test_protected_route_without_token(self, client: AsyncClient):
        """Protected routes return 401 without a token."""
        response = await client.get("/api/v1/users/me")
        assert response.status_code == 401
        assert get_error_code(response) == "AUTH_TOKEN_MISSING"

    async def test_protected_route_with_invalid_token(self, client: AsyncClient):
        """Invalid JWT returns 401."""
        response = await client.get(
            "/api/v1/users/me",
            headers=auth_header("invalid.jwt.token"),
        )
        assert response.status_code == 401

    async def test_protected_route_with_valid_token(
        self, client: AsyncClient, regular_user
    ):
        """Valid token grants access to protected routes."""
        response = await client.get(
            "/api/v1/users/me",
            headers=auth_header(regular_user["access_token"]),
        )
        assert response.status_code == 200
        assert response.json()["data"]["email"] == regular_user["email"]