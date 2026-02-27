"""

Integration tests for admin endpoints.
Verifies RBAC enforcement and admin operations.
"""

import pytest
from httpx import AsyncClient

from tests.conftest import create_test_user, get_error_code, login_user, auth_header


class TestRBACEnforcement:

    async def test_regular_user_cannot_access_admin(
        self, client: AsyncClient, regular_user
    ):
        """Regular users get 403 on admin endpoints."""
        response = await client.get(
            "/api/v1/admin/users",
            headers=auth_header(regular_user["access_token"]),
        )
        assert response.status_code == 403
        assert get_error_code(response) == "AUTH_INSUFFICIENT_PERMISSIONS"

    async def test_admin_can_list_users(
        self, client: AsyncClient, admin_user
    ):
        """Admin can list all users."""
        response = await client.get(
            "/api/v1/admin/users",
            headers=auth_header(admin_user["access_token"]),
        )
        assert response.status_code == 200
        data = response.json()["data"]
        assert "users" in data
        assert "total" in data

    async def test_unauthenticated_cannot_access_admin(
        self, client: AsyncClient
    ):
        """Unauthenticated requests cannot access admin endpoints."""
        response = await client.get("/api/v1/admin/users")
        assert response.status_code == 401


class TestUserManagement:

    async def test_admin_can_get_user(
        self, client: AsyncClient, admin_user, regular_user
    ):
        """Admin can get details for any user."""
        response = await client.get(
            f"/api/v1/admin/users/{regular_user['user_id']}",
            headers=auth_header(admin_user["access_token"]),
        )
        assert response.status_code == 200
        assert response.json()["data"]["email"] == regular_user["email"]

    async def test_admin_can_deactivate_user(
        self, client: AsyncClient, admin_user, regular_user
    ):
        """Admin can deactivate a user account."""
        response = await client.patch(
            f"/api/v1/admin/users/{regular_user['user_id']}/status",
            json={"is_active": False},
            headers=auth_header(admin_user["access_token"]),
        )
        assert response.status_code == 200
        assert response.json()["data"]["is_active"] is False

    async def test_deactivated_user_cannot_access_api(
        self, client: AsyncClient, admin_user, regular_user
    ):
        """Deactivated user's token is immediately rejected."""
        # Deactivate
        await client.patch(
            f"/api/v1/admin/users/{regular_user['user_id']}/status",
            json={"is_active": False},
            headers=auth_header(admin_user["access_token"]),
        )

        # Try to use their token
        response = await client.get(
            "/api/v1/users/me",
            headers=auth_header(regular_user["access_token"]),
        )
        assert response.status_code == 403
        assert get_error_code(response) == "AUTH_ACCOUNT_DISABLED"

    async def test_admin_can_update_roles(
        self, client: AsyncClient, admin_user, regular_user
    ):
        """Admin can change a user's roles."""
        response = await client.patch(
            f"/api/v1/admin/users/{regular_user['user_id']}/roles",
            json={"roles": ["user", "moderator"]},
            headers=auth_header(admin_user["access_token"]),
        )
        assert response.status_code == 200
        roles = response.json()["data"]["roles"]
        assert "moderator" in roles
        assert "user" in roles

    async def test_admin_cannot_remove_own_admin_role(
        self, client: AsyncClient, admin_user
    ):
        """Admin cannot remove their own admin role."""
        response = await client.patch(
            f"/api/v1/admin/users/{admin_user['user_id']}/roles",
            json={"roles": ["user"]},
            headers=auth_header(admin_user["access_token"]),
        )
        assert response.status_code == 400
        assert "admin" in response.json()["message"].lower()

    async def test_admin_search_users(
        self, client: AsyncClient, admin_user, regular_user
    ):
        """Admin can search users by email."""
        email_part = regular_user["email"].split("@")[0]
        response = await client.get(
            f"/api/v1/admin/users?search={email_part}",
            headers=auth_header(admin_user["access_token"]),
        )
        assert response.status_code == 200
        users = response.json()["data"]["users"]
        assert any(u["email"] == regular_user["email"] for u in users)