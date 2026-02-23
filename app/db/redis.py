"""

Redis connection management.

WHY A CONNECTION POOL?
Same reason as the database pool. Creating a new Redis TCP connection
per request is wasteful. A pool maintains persistent connections that
requests share.

WHY redis[hiredis]?
hiredis is a C-based Redis protocol parser. The pure-Python parser works
fine, but hiredis is significantly faster for parsing Redis responses.
It's a drop-in speedup — just install it and redis-py uses it automatically.
"""

from redis.asyncio import ConnectionPool, Redis

from app.config import settings

# Module-level pool — created once when the module is first imported.
# All Redis clients created from this pool share the same connections.
redis_pool: ConnectionPool | None = None


async def init_redis_pool() -> None:
    """
    Initialize the Redis connection pool.
    Called once at application startup (in app/main.py lifespan).

    max_connections=20: Maximum number of simultaneous Redis connections.
    decode_responses=True: Automatically decode bytes to str.
        Without this, every Redis response is bytes (b"value" instead of "value").
    """
    global redis_pool
    redis_pool = ConnectionPool.from_url(
        settings.redis_url,
        max_connections=20,
        decode_responses=True,
    )


async def close_redis_pool() -> None:
    """
    Gracefully close all connections in the pool.
    Called at application shutdown.
    """
    global redis_pool
    if redis_pool:
        await redis_pool.aclose()
        redis_pool = None


def get_redis() -> Redis:
    """
    Returns a Redis client connected to the pool.

    NOTE: This is NOT a FastAPI dependency that yields — Redis clients
    are lightweight and don't need the same careful lifecycle management
    as database sessions. We just get a client and use it directly.

    Usage in services:
        from app.db.redis import get_redis
        redis = get_redis()
        await redis.set("key", "value", ex=300)
        value = await redis.get("key")
    """
    if redis_pool is None:
        raise RuntimeError(
            "Redis pool not initialized. "
            "Make sure init_redis_pool() is called at startup."
        )
    return Redis(connection_pool=redis_pool)


async def check_redis_connection() -> bool:
    """
    Verify Redis is reachable. Used in the health check endpoint.
    Returns True if connected, False otherwise.
    """
    try:
        redis = get_redis()
        await redis.ping()
        return True
    except Exception:
        return False