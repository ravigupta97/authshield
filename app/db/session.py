
"""

Async SQLAlchemy engine and session factory.

WHY ASYNC?
FastAPI is built on ASGI and supports async natively. If we used
synchronous SQLAlchemy, every database call would BLOCK the event loop,
destroying our concurrency gains. Async SQLAlchemy + asyncpg lets us
handle many simultaneous requests efficiently.

WHY CONNECTION POOLING?
Creating a new database connection for every request is expensive
(TLS handshake, authentication, etc.). A pool maintains a set of
reusable connections. Requests borrow a connection, use it, and
return it to the pool. Much faster.
"""

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

from app.config import settings

# Create the async engine.
# pool_pre_ping=True: Before using a connection from the pool,
#   test it with a lightweight "ping". Prevents using stale/dead connections.
# echo=True in dev: Logs every SQL statement. Invaluable for debugging.
#   Set echo=False in production for performance.
engine = create_async_engine(
    settings.database_url,
    echo=settings.is_development,   # Log SQL in dev, not in prod
    pool_pre_ping=True,
    pool_size=10,           # Keep 10 connections alive in the pool
    max_overflow=20,        # Allow 20 more when pool is exhausted
    pool_recycle=3600,      # Recycle connections after 1 hour (prevents stale connections)
)

# Session factory — creates new AsyncSession instances.
# expire_on_commit=False: After commit(), don't expire loaded objects.
#   Without this, accessing attributes after commit raises lazy-load errors
#   in async contexts (async doesn't support implicit lazy loading).
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency that provides a database session per request.

    Usage in route handlers:
        @router.get("/something")
        async def my_route(db: AsyncSession = Depends(get_db)):
            ...

    HOW IT WORKS:
    - 'async with AsyncSessionLocal()' creates a session and guarantees
      it's closed when the block exits (even if an exception occurs).
    - 'yield' hands the session to the route handler.
    - After the route handler finishes, control returns here and
      the session is closed.
    - This pattern ensures no connection leaks, ever.
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            # If anything goes wrong in the route handler,
            # roll back any partial changes before closing.
            await session.rollback()
            raise
        finally:
            await session.close()