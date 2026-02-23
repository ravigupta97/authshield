"""

Stores refresh tokens for rotation and reuse detection.

KEY CONCEPTS:
- token_hash: We store a HASH of the token, not the raw token.
  If the DB is breached, attackers can't use the hashes.

- family_id: Groups all tokens from a single login together.
  Token A → rotated to → Token B → rotated to → Token C
  All share the same family_id.
  If Token A (already used) is presented again, we revoke
  ALL tokens where family_id matches — killing the attacker's
  current token too.

- is_used: Set to True when this token is rotated.
  Presenting a used token = REUSE DETECTED = revoke family.

- is_revoked: Set to True on logout or forced revocation.
  Presenting a revoked token = just invalid, no alarm.
"""

import uuid

from sqlalchemy import Boolean, DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, UUIDMixin


class RefreshToken(UUIDMixin, Base):
    """
    Represents a single refresh token in a rotation chain.

    Lifecycle:
    CREATED (is_used=False, is_revoked=False)
        → USED (is_used=True) when rotated — new token created
        → REVOKED (is_revoked=True) on logout or security event
    """

    __tablename__ = "refresh_tokens"

    # ── Ownership ─────────────────────────────────────────────────
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,  # We query by user_id when revoking all user tokens
    )

    # ── Token Data ────────────────────────────────────────────────
    # bcrypt hash of the actual token string sent to the client.
    token_hash: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    # Groups all tokens from one login session together.
    # Used for reuse detection — if reuse detected, revoke entire family.
    family_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        index=True,
        default=uuid.uuid4,  # Each login creates a new family
    )

    # ── Status Flags ──────────────────────────────────────────────
    # True after this token has been rotated (used to get a new token).
    # Presenting a used token triggers reuse detection.
    is_used: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    # True after explicit logout or admin revocation.
    is_revoked: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )

    # ── Expiry ────────────────────────────────────────────────────
    expires_at: Mapped[uuid.UUID] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    # Self-referential FK: points to the token that replaced this one.
    # Token A → replaced_by → Token B → replaced_by → Token C
    # Lets us trace the full rotation chain for debugging.
    replaced_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("refresh_tokens.id", ondelete="SET NULL"),
        nullable=True,
    )

    # ── Relationships ─────────────────────────────────────────────
    user: Mapped["User"] = relationship(  # type: ignore[name-defined]
        "User",
        back_populates="refresh_tokens",
    )
    session: Mapped["Session | None"] = relationship(  # type: ignore[name-defined]
        "Session",
        back_populates="refresh_token",
        uselist=False,  # One-to-one: each token belongs to one session
    )

    def __repr__(self) -> str:
        return (
            f"<RefreshToken id={self.id} "
            f"user_id={self.user_id} "
            f"is_used={self.is_used} "
            f"is_revoked={self.is_revoked}>"
        )