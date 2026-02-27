"""

Integration tests for session management.
"""

import pytest
from httpx import AsyncClient

from tests.conftest import create_test_user, get_error_code, login_user, auth_header


class TestSessionListing:

    async def test_list_sessions_requires_auth(self, client: AsyncClient):
        """Session listing requires authentication."""
        response = await client.get("/api/v1/sessions")
        assert response.status_code == 401

    async def test_list_sessions_shows_current(
        self, client: AsyncClient, regular_user
    ):
        """Session list marks the current session correctly."""
        response = await client.get(
            "/api/v1/sessions",
            headers=auth_header(regular_user["access_token"]),
        )
        assert response.status_code == 200
        data = response.json()["data"]

        current_sessions = [s for s in data["sessions"] if s["is_current"]]
        assert len(current_sessions) == 1

    async def test_multiple_logins_create_multiple_sessions(
        self, client: AsyncClient
    ):
        """Each login creates a separate session."""
        user = await create_test_user(client)

        tokens1 = await login_user(client, user["email"], user["password"])
        tokens2 = await login_user(client, user["email"], user["password"])

        response = await client.get(
            "/api/v1/sessions",
            headers=auth_header(tokens1["access_token"]),
        )
        sessions = response.json()["data"]["sessions"]
        assert len(sessions) >= 2


class TestSessionRevocation:

    async def test_revoke_other_session(self, client: AsyncClient):
        """Can revoke another session without affecting current one."""
        user = await create_test_user(client)
        tokens1 = await login_user(client, user["email"], user["password"])
        tokens2 = await login_user(client, user["email"], user["password"])

        # Get sessions from token1's perspective
        sessions_resp = await client.get(
            "/api/v1/sessions",
            headers=auth_header(tokens1["access_token"]),
        )
        sessions = sessions_resp.json()["data"]["sessions"]
        other = [s for s in sessions if not s["is_current"]][0]

        # Revoke the other session
        response = await client.delete(
            f"/api/v1/sessions/{other['id']}",
            headers=auth_header(tokens1["access_token"]),
        )
        assert response.status_code == 200

        # token1 still works
        me_resp = await client.get(
            "/api/v1/users/me",
            headers=auth_header(tokens1["access_token"]),
        )
        assert me_resp.status_code == 200

        # token2's refresh token is revoked
        refresh_resp = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": tokens2["refresh_token"]},
        )
        assert refresh_resp.status_code == 401

    async def test_revoke_current_session(
        self, client: AsyncClient, regular_user
    ):
        """Revoking current session blacklists the access token."""
        sessions_resp = await client.get(
            "/api/v1/sessions",
            headers=auth_header(regular_user["access_token"]),
        )
        current = [
            s for s in sessions_resp.json()["data"]["sessions"]
            if s["is_current"]
        ][0]

        await client.delete(
            f"/api/v1/sessions/{current['id']}",
            headers=auth_header(regular_user["access_token"]),
        )

        # Token is now blacklisted
        response = await client.get(
            "/api/v1/users/me",
            headers=auth_header(regular_user["access_token"]),
        )
        assert response.status_code == 401
        assert get_error_code(response) == "AUTH_TOKEN_REVOKED"

    async def test_cannot_revoke_another_users_session(
        self, client: AsyncClient
    ):
        """Cannot revoke sessions belonging to other users."""
        user1 = await create_test_user(client)
        user2 = await create_test_user(client)

        tokens1 = await login_user(client, user1["email"], user1["password"])
        tokens2 = await login_user(client, user2["email"], user2["password"])

        # Get user2's session ID
        sessions_resp = await client.get(
            "/api/v1/sessions",
            headers=auth_header(tokens2["access_token"]),
        )
        user2_session = sessions_resp.json()["data"]["sessions"][0]

        # Try to revoke it with user1's token
        response = await client.delete(
            f"/api/v1/sessions/{user2_session['id']}",
            headers=auth_header(tokens1["access_token"]),
        )
        assert response.status_code == 404  # Not found (ownership check)

    async def test_revoke_nonexistent_session(
        self, client: AsyncClient, regular_user
    ):
        """Revoking non-existent session returns 404."""
        fake_id = "00000000-0000-0000-0000-000000000000"
        response = await client.delete(
            f"/api/v1/sessions/{fake_id}",
            headers=auth_header(regular_user["access_token"]),
        )
        assert response.status_code == 404