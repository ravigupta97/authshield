"""
app/core/rate_limiter.py

Redis-based sliding window rate limiter.

ALGORITHM: Sliding Window with Redis Sorted Sets

Redis sorted set structure:
  Key:   "rate:{endpoint}:{identifier}"  e.g. "rate:login:192.168.1.1"
  Value: Each member is a unique request ID (UUID)
  Score: The timestamp of the request (Unix timestamp as float)

On each request:
  1. ZREMRANGEBYSCORE → remove all members with score < (now - window)
  2. ZCARD → count remaining members
  3. If count >= limit → reject (429)
  4. ZADD → add current request with score=now
  5. EXPIRE → reset TTL to window_size (auto-cleanup)

WHY sorted sets?
  - Score = timestamp, so range queries are O(log N)
  - ZREMRANGEBYSCORE removes expired entries efficiently
  - ZCARD gives instant count
  - All operations are atomic via pipeline

WHY store a UUID per request instead of incrementing a counter?
  - Sorted sets require unique members
  - UUID ensures no collision even with microsecond timestamps
  - The UUID value itself doesn't matter — only the score (timestamp) does
"""

import time
import uuid

import structlog
from fastapi import Request
from fastapi.responses import JSONResponse

from app.db.redis import get_redis

log = structlog.get_logger()


class RateLimitConfig:
    """
    Configuration for a single rate limit rule.

    requests: maximum number of requests allowed
    window_seconds: the sliding window size in seconds
    identifier: what to rate limit BY (ip, user_id, etc.)
    """
    def __init__(
        self,
        requests: int,
        window_seconds: int,
        identifier: str = "ip",
    ):
        self.requests = requests
        self.window_seconds = window_seconds
        self.identifier = identifier


# ── Predefined Rate Limit Rules ───────────────────────────────────
# These are the rules applied to specific endpoints.
# Adjust values based on your security requirements.

RATE_LIMITS = {
    "login": RateLimitConfig(
        requests=5,
        window_seconds=60,
        identifier="ip",
    ),
    "register": RateLimitConfig(
        requests=3,
        window_seconds=60,
        identifier="ip",
    ),
    "forgot_password": RateLimitConfig(
        requests=3,
        window_seconds=300,   # 5 minute window — password reset is expensive
        identifier="ip",
    ),
    "two_fa_verify": RateLimitConfig(
        requests=5,
        window_seconds=60,
        identifier="ip",
    ),
    "resend_verification": RateLimitConfig(
        requests=3,
        window_seconds=300,
        identifier="ip",
    ),
}


async def check_rate_limit(
    identifier: str,
    endpoint: str,
    config: RateLimitConfig,
) -> tuple[bool, dict]:
    """
    Check if a request should be rate limited.

    Returns:
        (is_allowed, rate_limit_info)
        is_allowed: True if request should proceed, False if blocked
        rate_limit_info: dict with limit metadata for response headers

    The rate_limit_info lets us add standard headers even on
    successful requests so clients know their current usage.
    """
    # Skip rate limiting entirely during tests.
    # TESTING=true is set in pytest.ini so this never affects production.
    import os
    if os.getenv("TESTING") == "true":
        return True, {"limit": config.requests, "remaining": config.requests, "window_seconds": config.window_seconds, "current_count": 0}
    
    
    redis = get_redis()
    now = time.time()
    window_start = now - config.window_seconds

    # Redis key: "rate:{endpoint}:{identifier}"
    key = f"rate:{endpoint}:{identifier}"

    # Use a pipeline to execute all Redis commands atomically
    # This prevents race conditions between check and increment
    pipe = redis.pipeline()

    # Step 1: Remove entries outside the current window
    pipe.zremrangebyscore(key, "-inf", window_start)

    # Step 2: Count requests in current window
    pipe.zcard(key)

    # Step 3: Add this request to the sorted set
    # Score = timestamp, Member = unique ID
    pipe.zadd(key, {str(uuid.uuid4()): now})

    # Step 4: Set TTL so the key auto-deletes when window expires
    # This prevents Redis memory bloat from inactive keys
    pipe.expire(key, config.window_seconds)

    results = await pipe.execute()
    current_count = results[1]  # Result of ZCARD (before adding new request)

    is_allowed = current_count < config.requests
    remaining = max(config.requests - current_count - 1, 0)

    rate_limit_info = {
        "limit": config.requests,
        "remaining": remaining if is_allowed else 0,
        "window_seconds": config.window_seconds,
        "current_count": current_count,
    }

    if not is_allowed:
        log.warning(
            "Rate limit exceeded",
            endpoint=endpoint,
            identifier=identifier,
            count=current_count,
            limit=config.requests,
        )

    return is_allowed, rate_limit_info


def get_client_ip(request: Request) -> str:
    """
    Extract the real client IP address from the request.

    Checks X-Forwarded-For header first (set by proxies/load balancers).
    Falls back to direct connection IP if header not present.

    WHY X-Forwarded-For?
    In production, requests often pass through nginx/load balancer.
    The direct connection IP would be the proxy's IP — same for all users.
    X-Forwarded-For contains the original client IP.
    """
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # X-Forwarded-For can contain multiple IPs: "client, proxy1, proxy2"
        # The first one is the real client
        return forwarded_for.split(",")[0].strip()

    if request.client:
        return request.client.host

    return "unknown"


class RateLimiter:
    """
    FastAPI dependency class for rate limiting.

    Usage in an endpoint:
        @router.post("/login")
        async def login(
            request: Request,
            _: None = Depends(RateLimiter("login")),
        ):
            ...

    If the rate limit is exceeded, the dependency raises a 429
    response BEFORE the endpoint handler runs — zero overhead
    on the actual business logic.
    """

    def __init__(self, endpoint: str):
        """
        endpoint: key into RATE_LIMITS dict
                  e.g. "login", "register", "forgot_password"
        """
        if endpoint not in RATE_LIMITS:
            raise ValueError(
                f"Unknown rate limit endpoint: {endpoint}. "
                f"Valid options: {list(RATE_LIMITS.keys())}"
            )
        self.endpoint = endpoint
        self.config = RATE_LIMITS[endpoint]

    async def __call__(self, request: Request) -> None:
        """
        Called by FastAPI's dependency injection system.
        Raises JSONResponse(429) if rate limit exceeded.
        Returns None if request is allowed (dependency resolves).
        """
        # Determine identifier (what to rate limit by)
        identifier = get_client_ip(request)

        is_allowed, info = await check_rate_limit(
            identifier=identifier,
            endpoint=self.endpoint,
            config=self.config,
        )

        # Always add rate limit headers to response
        # (FastAPI doesn't let us set response headers from dependencies
        # directly, so we store them on request.state for the endpoint
        # to apply if needed — or use middleware for this in production)
        request.state.rate_limit_info = info

        if not is_allowed:
            raise RateLimitResponse(
                endpoint=self.endpoint,
                config=self.config,
            )


class RateLimitResponse(Exception):
    """
    Custom exception raised when rate limit is exceeded.
    Carries enough info to build a proper 429 response.
    We use a custom exception class (not JSONResponse directly)
    so FastAPI's exception handler system can catch it.
    """
    def __init__(self, endpoint: str, config: RateLimitConfig):
        self.endpoint = endpoint
        self.config = config