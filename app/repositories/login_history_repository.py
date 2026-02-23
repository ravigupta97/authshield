"""

Append-only audit log of all login attempts.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.login_history import LoginHistory


class LoginHistoryRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def record(
        self,
        status: str,
        user_id: uuid.UUID | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        failure_reason: str | None = None,
    ) -> LoginHistory:
        """
        Record a login attempt.

        status: 'success' or 'failed'
        failure_reason: only on failure e.g. 'wrong_password'

        This is append-only — we never update these records.
        """
        entry = LoginHistory(
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            status=status,
            failure_reason=failure_reason,
            created_at=datetime.now(timezone.utc),
        )
        self.db.add(entry)
        await self.db.flush()
        return entry