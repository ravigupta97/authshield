"""

Alembic migration environment configuration.
This file tells Alembic how to connect to the database and
where to find the SQLAlchemy models for schema comparison.
"""

import asyncio
from logging.config import fileConfig

from sqlalchemy import pool
from sqlalchemy.engine import Connection

from alembic import context

# Import settings to get the database URL
from app.config import settings
from sqlalchemy.ext.asyncio import create_async_engine

# Import Base and ALL models so Alembic can see them
# If you add a new model file, import it here too
from app.db.base import Base
import app.models  # noqa: F401 — registers all models with Base.metadata
# Models will be imported here as we create them:
# from app.models.user import User
# from app.models.role import Role, user_roles
# from app.models.refresh_token import RefreshToken
# from app.models.session import Session
# from app.models.login_history import LoginHistory

config = context.config

# Override the sqlalchemy.url with our settings
# This way we don't need to put credentials in alembic.ini
config.set_main_option("sqlalchemy.url", settings.database_url)

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# This is the MetaData object that Alembic uses to detect schema changes.
# It must include all your models.
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations without a live database connection."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,  # Detect column type changes
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """Run migrations using an async engine."""
    connectable = create_async_engine(   # ← direct engine, not from config
        settings.database_url,
        poolclass=pool.NullPool,
        connect_args={"ssl": "require"}, # ← SSL via connect_args
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    """Run migrations with a live database connection."""
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()