"""

Aggregates all endpoint routers into a single v1 router.
As we build each feature, we import and include it here.
"""

from fastapi import APIRouter

from app.api.v1.endpoints.health import router as health_router
from app.api.v1.endpoints.auth import router as auth_router

# We'll uncomment these as we build each feature:
from app.api.v1.endpoints.oauth import router as oauth_router
from app.api.v1.endpoints.passwords import router as passwords_router
from app.api.v1.endpoints.users import router as users_router
from app.api.v1.endpoints.sessions import router as sessions_router
# from app.api.v1.endpoints.two_factor import router as two_factor_router
from app.api.v1.endpoints.admin import router as admin_router

api_router = APIRouter()

# Health check — always available
api_router.include_router(health_router, tags=["Health"])
api_router.include_router(auth_router, prefix="/auth", tags=["Authentication"])
api_router.include_router(users_router, prefix="/users", tags=["Users"])
api_router.include_router(passwords_router, prefix="/auth", tags=["Password Management"])

# Auth routes (added as we build)
api_router.include_router(oauth_router, prefix="/auth/oauth", tags=["OAuth"])
api_router.include_router(sessions_router, prefix="/sessions", tags=["Sessions"])
# api_router.include_router(two_factor_router, prefix="/auth/2fa", tags=["Two-Factor Auth"])
api_router.include_router(admin_router, prefix="/admin", tags=["Admin"])