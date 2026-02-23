"""

SQLAlchemy declarative base class.
All ORM models inherit from Base, which registers them with SQLAlchemy's
metadata. This metadata is what Alembic uses to detect schema changes
and generate migrations.

We also define a common base with shared columns (id, created_at, updated_at)
that every table will have. DRY principle — define once, inherit everywhere.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """
    Base class for all SQLAlchemy models.

    DeclarativeBase is the modern SQLAlchemy 2.0 way to define models.
    It replaces the older declarative_base() function.
    """
    pass


class TimestampMixin:
    """
    Mixin that adds created_at and updated_at columns to any model.

    'Mixin' is a design pattern: a class with methods/attributes
    meant to be mixed into other classes via multiple inheritance.
    We're not inheriting from Base here — models will inherit from
    BOTH Base AND TimestampMixin.

    server_default=func.now(): The database sets this value,
        not Python. Avoids timezone issues between app server and DB.
    onupdate=func.now(): Automatically updates to current time
        whenever the row is modified.
    """

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class UUIDMixin:
    """
    Mixin that adds a UUID primary key to any model.

    WHY UUID over auto-increment integer?
    - Security: Sequential IDs leak information. UUID v4 is random.
    - Distribution: UUIDs are globally unique without coordination.
    - Unpredictability: Can't guess other users' IDs.

    default=uuid.uuid4: Python generates the UUID before insert.
    This means the ID is available immediately after object creation,
    before the database INSERT. Useful for logging and response building.
    """

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        nullable=False,
    )