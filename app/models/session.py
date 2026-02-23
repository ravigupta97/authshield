"""

Tracks active login sessions across devices.

Each login creates one Session record. Users can see all their
active sessions (like Google's "Manage devices" page) and revoke
individual ones remotely.

A Session is linked 1-to-1 with a RefreshToken because:
- The refresh token IS the session credential
- Revoking a session = revoking its refresh token
- They live and die together
"""

import uuid

from sqlalchemy import Boolean, DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, UUIDMixin


class Session(UUIDMixin, Base):
    """
    Represents one active login session on one device.
    """

    __tablename__ = "sessions"

    # ── Ownership ─────────────────────────────────────────────────
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Link to the refresh token that keeps this session alive.
    # When the refresh token is revoked, this session is dead.
    refresh_token_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("refresh_tokens.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,  # One session per refresh token
    )

    # ── Device / Client Info ──────────────────────────────────────
    # IPv4 (max 15 chars) or IPv6 (max 45 chars)
    ip_address: Mapped[str | None] = mapped_column(
        String(45),
        nullable=True,
    )
    # Raw User-Agent header from the login request
    user_agent: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
    )
    # Human-readable device info parsed from user_agent
    # e.g. "Chrome on Windows", "Safari on iPhone"
    device_info: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    # ── Status ────────────────────────────────────────────────────
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )
    # Updated every time the session's refresh token is used.
    # Shows users "last active" time on the sessions page.
    last_active_at: Mapped[uuid.UUID] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # ── Timing ────────────────────────────────────────────────────
    created_at: Mapped[uuid.UUID] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    # Matches the refresh token's expires_at
    expires_at: Mapped[uuid.UUID] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    # ── Relationships ─────────────────────────────────────────────
    user: Mapped["User"] = relationship(  # type: ignore[name-defined]
        "User",
        back_populates="sessions",
    )
    refresh_token: Mapped["RefreshToken"] = relationship(  # type: ignore[name-defined]
        "RefreshToken",
        back_populates="session",
    )

    def __repr__(self) -> str:
        return (
            f"<Session id={self.id} "
            f"user_id={self.user_id} "
            f"is_active={self.is_active}>"
        )