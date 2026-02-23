"""
Immutable audit log of every login attempt (success or failure).

WHY IMMUTABLE?
Audit logs should never be edited or deleted (except by retention policy).
We never UPDATE rows here — only INSERT. This gives you a trustworthy
record of all authentication events.

WHY A SEPARATE TABLE?
- Keeps the users table clean and fast
- Failed attempts don't pollute user data
- Easy to query "all failed attempts in the last hour from this IP"
- Compliance: many regulations require login audit trails
"""

import uuid

from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID
from app.db.base import Base, UUIDMixin


class LoginHistory(UUIDMixin, Base):
    """
    Records every login attempt with its outcome.
    Never updated after creation.
    """

    __tablename__ = "login_history"

    # ── Who ───────────────────────────────────────────────────────
    # SET NULL on delete so we keep the audit record even if user
    # is deleted. Important for compliance/forensics.
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # ── Where From ────────────────────────────────────────────────
    ip_address: Mapped[str | None] = mapped_column(
        String(45),
        nullable=True,
    )
    user_agent: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
    )

    # ── What Happened ─────────────────────────────────────────────
    # 'success' or 'failed'
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )
    # Only set on failure. e.g. "wrong_password", "unverified_email"
    failure_reason: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    # ── When ──────────────────────────────────────────────────────
    created_at: Mapped[uuid.UUID] = mapped_column(
        String(50),   # stored as ISO string for simplicity in audit logs
        nullable=False,
    )

    # ── Relationships ─────────────────────────────────────────────
    user: Mapped["User | None"] = relationship(  # type: ignore[name-defined]
        "User",
        back_populates="login_history",
    )

    def __repr__(self) -> str:
        return (
            f"<LoginHistory id={self.id} "
            f"user_id={self.user_id} "
            f"status={self.status}>"
        )