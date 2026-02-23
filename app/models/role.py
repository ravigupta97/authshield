"""

Role model and the user_roles association table.

WHY A SEPARATE ASSOCIATION TABLE (user_roles)?
A user can have MANY roles. A role can belong to MANY users.
This is a Many-to-Many relationship. In SQL, you can't store a list
inside a column — you need a third "junction" table that holds pairs
of (user_id, role_id).

user_roles is that junction table.
"""

import uuid
from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, String, Table, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDMixin

# Association table — NOT a full model class, just a Table object.
# We don't need to query this table directly; SQLAlchemy manages it
# automatically when you do user.roles.append(role).
user_roles = Table(
    "user_roles",
    Base.metadata,
    Column(
        "user_id",
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "role_id",
        UUID(as_uuid=True),
        ForeignKey("roles.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "assigned_at",
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    ),
)


class Role(UUIDMixin, TimestampMixin, Base):
    """
    Represents a permission role (user, admin, moderator).

    Seeded once at startup — these three roles are always present.
    Admins can't create new role types via the API (keeps it generic).
    """

    __tablename__ = "roles"

    name: Mapped[str] = mapped_column(
        String(50),
        unique=True,
        nullable=False,
        index=True,
    )
    description: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    # Relationship back to users (via user_roles association table)
    # 'secondary' tells SQLAlchemy to use user_roles as the join table
    users: Mapped[list["User"]] = relationship(  # type: ignore[name-defined]
        "User",
        secondary=user_roles,
        back_populates="roles",
    )

    def __repr__(self) -> str:
        return f"<Role id={self.id} name={self.name}>"
