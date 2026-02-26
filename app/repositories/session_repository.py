"""

Database operations for user sessions.
"""

import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.config import settings
from app.models.session import Session


class SessionRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create(
        self,
        user_id: uuid.UUID,
        refresh_token_id: uuid.UUID,
        ip_address: str | None = None,
        user_agent: str | None = None,
        device_info: str | None = None,
    ) -> Session:
        """Create a new session record on login."""
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(days=settings.refresh_token_expire_days)

        session = Session(
            user_id=user_id,
            refresh_token_id=refresh_token_id,
            ip_address=ip_address,
            user_agent=user_agent,
            device_info=device_info,
            is_active=True,
            last_active_at=now,
            created_at=now,
            expires_at=expires_at,
        )
        self.db.add(session)
        await self.db.flush()
        return session

    async def get_by_id(
        self,
        session_id: uuid.UUID,
    ) -> Session | None:
        result = await self.db.execute(
            select(Session).where(Session.id == session_id)
        )
        return result.scalar_one_or_none()

    async def get_by_refresh_token_id(
        self,
        refresh_token_id: uuid.UUID,
    ) -> Session | None:
        result = await self.db.execute(
            select(Session).where(Session.refresh_token_id == refresh_token_id)
        )
        return result.scalar_one_or_none()

    async def get_active_sessions_for_user(
        self,
        user_id: uuid.UUID,
    ) -> list[Session]:
        """Get all active sessions for a user (for the 'manage devices' page)."""
        result = await self.db.execute(
            select(Session)
            .where(Session.user_id == user_id)
            .where(Session.is_active == True)  # noqa: E712
            .order_by(Session.last_active_at.desc())
        )
        return list(result.scalars().all())

    async def deactivate(self, session: Session) -> None:
        """Deactivate a specific session (user revokes one device)."""
        session.is_active = False
        await self.db.flush()

    async def deactivate_all_for_user(self, user_id: uuid.UUID) -> None:
        """Deactivate all sessions for a user (logout all devices)."""
        await self.db.execute(
            update(Session)
            .where(Session.user_id == user_id)
            .where(Session.is_active == True)  # noqa: E712
            .values(is_active=False)
        )

    async def update_last_active(self, session: Session) -> None:
        """Update the last active timestamp (called on token refresh)."""
        session.last_active_at = datetime.now(timezone.utc)
        await self.db.flush()

    async def get_by_id_and_user(
        self,
        session_id: uuid.UUID,
        user_id: uuid.UUID,
    ) -> Session | None:
        """
        Fetch a session only if it belongs to the given user.
        Used for ownership validation before revocation.
        Returns None if session doesn't exist OR belongs to someone else.
        """
        result = await self.db.execute(
            select(Session)
            .where(Session.id == session_id)
            .where(Session.user_id == user_id)
            .where(Session.is_active == True)  # noqa: E712
        )
        return result.scalar_one_or_none()