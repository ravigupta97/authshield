"""

Business logic for session management.

Sessions represent active logins across devices. Each login
creates one session. Users can view and revoke their own sessions.

CURRENT SESSION DETECTION:
When listing sessions, we mark one as "is_current: True" — the
session that belongs to the JWT making this request. We get the
session_id from the JWT payload (we embedded it at login time).

This lets the frontend show "This device" next to the current
session and prevent the user from accidentally revoking it without
a warning.

REVOCATION:
Revoking a session does THREE things atomically:
1. Marks the session as inactive in DB
2. Marks the refresh token as revoked in DB
3. Blacklists the access token JTI in Redis (immediate effect)

Step 3 is what makes revocation truly instant. Without it, the
revoked session's access token would still work until it naturally
expires (up to 15 minutes). With Redis blacklisting, the token
is dead the moment we process the revocation.

PROBLEM: To blacklist the access token, we need its JTI. But we
only store the refresh token in the DB — not the access token.
SOLUTION: We store the session_id inside the JWT payload. The
current access token (from the Authorization header) contains its
own JTI. For OTHER sessions being revoked remotely, we can't
blacklist their current access token (we don't have it) — but
their refresh token is revoked, so they can't get new access
tokens. Their current access token dies naturally within 15 min.

This is an acceptable security trade-off. True instant revocation
of remote sessions would require storing access token JTIs in the
DB (expensive) or using very short token TTLs.
"""

import uuid
from datetime import datetime, timezone

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import (
    SessionNotFoundError,
    SessionOwnershipError,
)
from app.repositories.session_repository import SessionRepository
from app.repositories.token_repository import TokenRepository
from app.services.token_service import TokenService

log = structlog.get_logger()


class SessionService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.session_repo = SessionRepository(db)
        self.token_repo = TokenRepository(db)
        self.token_service = TokenService(db)

    async def list_user_sessions(
        self,
        user_id: uuid.UUID,
        current_session_id: uuid.UUID | None,
    ) -> list[dict]:
        """
        Return all active sessions for a user.

        current_session_id comes from the JWT payload (session_id claim).
        We use it to mark which session is "current" so the frontend
        can display "This device" and handle it specially.
        """
        sessions = await self.session_repo.get_active_sessions_for_user(
            user_id
        )

        result = []
        for session in sessions:
            result.append({
                "id": session.id,
                "ip_address": session.ip_address,
                "user_agent": session.user_agent,
                "device_info": session.device_info,
                # Mark the session making this request as current
                "is_current": session.id == current_session_id,
                "is_active": session.is_active,
                "last_active_at": session.last_active_at,
                "created_at": session.created_at,
                "expires_at": session.expires_at,
            })

        return result

    async def revoke_session(
        self,
        session_id: uuid.UUID,
        user_id: uuid.UUID,
        current_session_id: uuid.UUID | None = None,
        current_access_token_jti: str | None = None,
        current_access_token_exp: int | None = None,
    ) -> None:
        """
        Revoke a specific session by ID.

        Ownership check: the session must belong to user_id.
        This prevents users from revoking other users' sessions.

        If the session being revoked IS the current session,
        we also blacklist the current access token immediately
        (same as logout). For remote sessions, we can only revoke
        the refresh token — their current access token lives until
        natural expiry (max 15 min).
        """
        # Ownership check — only fetch if it belongs to this user
        session = await self.session_repo.get_by_id_and_user(
            session_id=session_id,
            user_id=user_id,
        )

        if not session:
            # Either doesn't exist OR belongs to someone else.
            # We give the same error for both — don't leak info.
            raise SessionNotFoundError()

        # Revoke the associated refresh token
        refresh_token = await self.token_repo.get_by_session(
            session.refresh_token_id
        )
        if refresh_token and not refresh_token.is_revoked:
            await self.token_repo.revoke_token(refresh_token)

        # Deactivate the session
        await self.session_repo.deactivate(session)

        # If this is the CURRENT session, blacklist the access token too
        # (for remote sessions we don't have the access token JTI)
        is_current_session = (
            current_access_token_jti is not None
            and current_session_id == session_id
        )
        if is_current_session and current_access_token_jti:
            remaining = 0
            if current_access_token_exp:
                now = datetime.now(timezone.utc).timestamp()
                remaining = max(int(current_access_token_exp - now), 0)
            await self.token_service.blacklist_access_token(
                jti=current_access_token_jti,
                expires_in_seconds=remaining,
            )

        await self.db.commit()

        log.info(
            "Session revoked",
            session_id=str(session_id),
            user_id=str(user_id),
            was_current_session=is_current_session,
        )