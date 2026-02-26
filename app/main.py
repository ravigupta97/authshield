"""

FastAPI application factory and lifespan management.

This is the entry point. It:
1. Creates the FastAPI app instance
2. Manages startup/shutdown (database pool, Redis pool)
3. Registers all middleware
4. Registers all routers
5. Registers exception handlers (maps our custom exceptions to HTTP responses)
"""

from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import settings
from app.core.exceptions import (
    AccountDisabledError,
    AuthShieldException,
    EmailAlreadyRegisteredError,
    EmailNotVerifiedError,
    InsufficientPermissionsError,
    InvalidCredentialsError,
    InvalidResetTokenError,
    InvalidVerificationTokenError,
    PasswordMismatchError,
    RateLimitExceededError,
    RefreshTokenInvalidError,
    RefreshTokenReuseError,
    SamePasswordError,
    SessionNotFoundError,
    SessionOwnershipError,
    TokenExpiredError,
    TokenInvalidError,
    TokenRevokedError,
    TwoFactorInvalidError,
    TwoFactorRequiredError,
    TwoFactorNotEnabledError,
    TwoFactorAlreadyEnabledError,
    UserNotFoundError, 
)
from app.db.redis import close_redis_pool, init_redis_pool

log = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifespan context manager — runs code on startup and shutdown.

    STARTUP (before 'yield'): Initialize shared resources.
    SHUTDOWN (after 'yield'): Clean up gracefully.

    This replaces the older @app.on_event("startup") pattern.
    It's preferred because it's more explicit and testable.
    """
    # ── STARTUP ───────────────────────────────────────────────────
    log.info("Starting AuthShield", version=settings.app_version, env=settings.app_env)

    # Initialize Redis connection pool
    await init_redis_pool()
    log.info("Redis connection pool initialized")

    # Note: SQLAlchemy creates its pool lazily on first use.
    # We don't need to explicitly initialize it here.

    log.info("AuthShield started successfully")

    yield  # Application runs here

    # ── SHUTDOWN ──────────────────────────────────────────────────
    log.info("Shutting down AuthShield...")

    await close_redis_pool()
    log.info("Redis connection pool closed")

    log.info("AuthShield shutdown complete")


def create_application() -> FastAPI:
    """
    Application factory function.

    WHY A FACTORY?
    Wrapping app creation in a function makes it easy to create
    multiple instances (e.g., one for production, one with test config).
    It also makes the startup logic explicit and testable.
    """
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description=(
            "A standalone, generic, reusable authentication and authorization "
            "microservice. Plug it into any project — no modification needed."
        ),
        # Disable docs in production for security
        docs_url="/docs" if settings.is_development else None,
        redoc_url="/redoc" if settings.is_development else None,
        openapi_url="/openapi.json" if settings.is_development else None,
        lifespan=lifespan,
    )

    # ── Middleware ────────────────────────────────────────────────
    # IMPORTANT: Middleware is applied in REVERSE order.
    # The last middleware added is the FIRST to process requests.

    # CORS — must be added first (it's outermost)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,        # Allow cookies and Authorization headers
        allow_methods=["*"],           # Allow all HTTP methods
        allow_headers=["*"],           # Allow all headers
        expose_headers=["X-Request-ID"],  # Allow frontend to read this header
    )

    # ── Routers ───────────────────────────────────────────────────
    # We'll uncomment these as we build each feature
    from app.api.v1.router import api_router
    app.include_router(api_router, prefix="/api/v1")

    # ── Exception Handlers ────────────────────────────────────────
    register_exception_handlers(app)

    return app


def register_exception_handlers(app: FastAPI) -> None:
    """
    Map custom exceptions to HTTP responses.

    WHY HERE and not in each route?
    Centralized exception handling means:
    - Consistent response format across ALL endpoints
    - No try/except boilerplate in every route handler
    - One place to change error response format for the whole API
    """

    @app.exception_handler(InvalidCredentialsError)
    @app.exception_handler(TokenExpiredError)
    @app.exception_handler(TokenInvalidError)
    @app.exception_handler(TokenRevokedError)
    @app.exception_handler(RefreshTokenInvalidError)
    async def unauthorized_handler(request: Request, exc: AuthShieldException):
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={
                "status": "error",
                "message": exc.message,
                "error_code": exc.error_code,
                "details": exc.details,
            },
        )

    @app.exception_handler(RefreshTokenReuseError)
    async def reuse_handler(request: Request, exc: RefreshTokenReuseError):
        # 401 but we log this prominently — it means a token was stolen
        log.warning(
            "Refresh token reuse detected",
            path=request.url.path,
            ip=request.client.host if request.client else "unknown",
        )
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={
                "status": "error",
                "message": exc.message,
                "error_code": exc.error_code,
                "details": exc.details,
            },
        )

    @app.exception_handler(EmailNotVerifiedError)
    @app.exception_handler(AccountDisabledError)
    @app.exception_handler(InsufficientPermissionsError)
    @app.exception_handler(SessionOwnershipError)
    async def forbidden_handler(request: Request, exc: AuthShieldException):
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "status": "error",
                "message": exc.message,
                "error_code": exc.error_code,
                "details": exc.details,
            },
        )

    @app.exception_handler(TwoFactorRequiredError)
    async def two_factor_required_handler(request: Request, exc: TwoFactorRequiredError):
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "status": "error",                    
                "message": exc.message,
                "error_code": exc.error_code,
                "details": {
                    "temp_token": exc.temp_token,     
                    "hint": (
                        "Send temp_token + totp_code to "
                        "POST /auth/2fa/verify to complete login."
                    ),
                },
            },
        )

    @app.exception_handler(TwoFactorInvalidError)
    async def two_factor_invalid_handler(request: Request, exc: TwoFactorInvalidError):
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={
                "status": "error",
                "message": exc.message,
                "error_code": exc.error_code,
                "details": exc.details,
            },
        )
    
    @app.exception_handler(TwoFactorNotEnabledError)
    async def two_factor_not_enabled_handler(
        request: Request, 
        exc: TwoFactorNotEnabledError):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "status": "error",
                "message": exc.message,
                "error_code": exc.error_code,
                "details": exc.details,
            },
        )


    @app.exception_handler(TwoFactorAlreadyEnabledError)
    async def two_factor_already_enabled_handler(
        request: Request, 
        exc: TwoFactorAlreadyEnabledError):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "status": "error",
                "message": exc.message,
                "error_code": exc.error_code,
                "details": exc.details,
            },
        )

    @app.exception_handler(EmailAlreadyRegisteredError)
    async def conflict_handler(request: Request, exc: AuthShieldException):
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={
                "status": "error",
                "message": exc.message,
                "error_code": exc.error_code,
                "details": exc.details,
            },
        )

    @app.exception_handler(UserNotFoundError)
    @app.exception_handler(SessionNotFoundError)
    async def not_found_handler(request: Request, exc: AuthShieldException):
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={
                "status": "error",
                "message": exc.message,
                "error_code": exc.error_code,
                "details": exc.details,
            },
        )

    @app.exception_handler(InvalidVerificationTokenError)
    @app.exception_handler(InvalidResetTokenError)
    @app.exception_handler(PasswordMismatchError)
    @app.exception_handler(SamePasswordError)
    async def bad_request_handler(request: Request, exc: AuthShieldException):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "status": "error",
                "message": exc.message,
                "error_code": exc.error_code,
                "details": exc.details,
            },
        )

    @app.exception_handler(RateLimitExceededError)
    async def rate_limit_handler(request: Request, exc: RateLimitExceededError):
        retry_after = exc.details.get("retry_after", 60) if exc.details else 60
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            headers={"Retry-After": str(retry_after)},
            content={
                "status": "error",
                "message": exc.message,
                "error_code": exc.error_code,
                "details": exc.details,
            },
        )

    @app.exception_handler(AuthShieldException)
    async def generic_authshield_handler(request: Request, exc: AuthShieldException):
        """Catch-all for any AuthShield exception not handled above."""
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "status": "error",
                "message": exc.message,
                "error_code": exc.error_code,
                "details": exc.details,
            },
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception):
        """
        Last resort — catches any exception we didn't anticipate.
        Logs it fully but returns a generic message to the client.
        Never expose internal error details to the client in production.
        """
        log.error(
            "Unhandled exception",
            exc_type=type(exc).__name__,
            exc_msg=str(exc),
            path=request.url.path,
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "status": "error",
                "message": "An internal server error occurred.",
                "error_code": "SYS_INTERNAL_ERROR",
                "details": str(exc) if settings.is_development else None,
            },
        )


# Create the app instance
app = create_application()