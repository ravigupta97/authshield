"""

Immutable audit log of every login attempt (success or failure).
Never updated after creation — append only.
"""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, UUIDMixin


class LoginHistory(UUIDMixin, Base):
    """
    Records every login attempt with its outcome.
    Never updated after creation.
    """

    __tablename__ = "login_history"

    # SET NULL on delete so we keep the audit record even if
    # the user account is deleted. Important for forensics.
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    ip_address: Mapped[str | None] = mapped_column(
        String(45),
        nullable=True,
    )
    user_agent: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
    )

    # 'success' or 'failed'
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )

    # Only populated on failure
    # e.g. "wrong_password", "unverified_email", "account_disabled"
    failure_reason: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    # Relationship back to user (nullable because user may be deleted)
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