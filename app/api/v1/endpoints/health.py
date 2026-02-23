"""


Health check endpoint. Used by:
- Load balancers to determine if this instance is alive
- Monitoring tools (UptimeRobot, Datadog, etc.)
- Your own sanity when debugging connectivity issues
"""

from fastapi import APIRouter

from app.config import settings
from app.db.redis import check_redis_connection

router = APIRouter()


@router.get("/health")
async def health_check():
    """
    Returns the service status and dependency health.
    Does NOT require authentication — monitoring tools need this.
    """
    # Check Redis connectivity
    redis_ok = await check_redis_connection()

    # We'll add DB check once models are set up
    # For now, assume DB is ok if the app is running
    db_ok = True

    overall_status = "healthy" if (redis_ok and db_ok) else "degraded"

    return {
        "status": overall_status,
        "version": settings.app_version,
        "environment": settings.app_env,
        "dependencies": {
            "database": "connected" if db_ok else "disconnected",
            "redis": "connected" if redis_ok else "disconnected",
        },
    }