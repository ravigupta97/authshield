"""


The central model of the entire system.
Every other model relates back to User.

Design decisions explained inline.
"""

from sqlalchemy import Boolean, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDMixin
from app.models.role import user_roles


class User(UUIDMixin, TimestampMixin, Base):
    """
    Represents a registered user account.

    Supports two authentication methods:
    1. Email/Password (password_hash is set, oauth_provider is NULL)
    2. OAuth (password_hash is NULL, oauth_provider is 'google'/'github')

    A user CAN have both if they registered with email then linked OAuth.
    """

    __tablename__ = "users"

    # ── Identity ──────────────────────────────────────────────────
    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True,  # We query by email on every login — must be indexed
    )
    full_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    avatar_url: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
    )

    # ── Password Auth ─────────────────────────────────────────────
    # NULLABLE because OAuth users don't have passwords.
    # We NEVER store the raw password — only the bcrypt hash.
    password_hash: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    # ── Account Status ────────────────────────────────────────────
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )
    is_verified: Mapped[bool] = mapped_column(
        Boolean,
        default=False,   # Must verify email before logging in
        nullable=False,
    )

    # ── OAuth ─────────────────────────────────────────────────────
    # NULL for email/password users.
    # 'google' or 'github' for OAuth users.
    oauth_provider: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )
    # The ID assigned by the OAuth provider (not our UUID).
    # Used to look up returning OAuth users without email comparison.
    oauth_id: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    # ── Two-Factor Auth ───────────────────────────────────────────
    is_2fa_enabled: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    # The TOTP secret key. NULL until user enables 2FA.
    # In a high-security system you'd encrypt this at rest.
    totp_secret: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    # ── Relationships ─────────────────────────────────────────────
    # Many-to-Many with Role via user_roles table
    roles: Mapped[list["Role"]] = relationship(  # type: ignore[name-defined]
        "Role",
        secondary=user_roles,
        back_populates="users",
        lazy="selectin",  # Always load roles with user (we need them for RBAC)
    )

    # One-to-Many with RefreshToken
    refresh_tokens: Mapped[list["RefreshToken"]] = relationship(  # type: ignore[name-defined]
        "RefreshToken",
        back_populates="user",
        cascade="all, delete-orphan",  # Delete tokens when user is deleted
    )

    # One-to-Many with Session
    sessions: Mapped[list["Session"]] = relationship(  # type: ignore[name-defined]
        "Session",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    # One-to-Many with LoginHistory
    login_history: Mapped[list["LoginHistory"]] = relationship(  # type: ignore[name-defined]
        "LoginHistory",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    # ── Computed helpers ──────────────────────────────────────────
    @property
    def role_names(self) -> list[str]:
        """Returns list of role name strings. e.g. ['user', 'moderator']"""
        return [role.name for role in self.roles]

    @property
    def is_admin(self) -> bool:
        return "admin" in self.role_names

    def __repr__(self) -> str:
        return f"<User id={self.id} email={self.email}>"