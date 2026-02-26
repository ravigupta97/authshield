"""

HTTP layer for authentication endpoints.
Responsibilities:
- Parse HTTP requests
- Call the appropriate service method
- Return properly formatted HTTP responses
- Nothing else. No business logic here.
"""

from fastapi import APIRouter, Depends, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.rate_limiter import RateLimiter
from app.api.v1.dependencies import CurrentUser, get_db
from app.schemas.auth import (
    LoginRequest,
    LoginResponse,
    LogoutRequest,
    RefreshRequest,
    RefreshResponse,
    RegisterRequest,
    RegisterResponse,
    ResendVerificationRequest,
    VerifyEmailRequest,
)
from app.schemas.common import StandardResponse
from app.services.auth_service import AuthService

router = APIRouter()

# We need the raw token string for logout blacklisting
# auto_error=False so we can give a clean error message
bearer_scheme = HTTPBearer(auto_error=False)


@router.post(
    "/register",
    status_code=status.HTTP_201_CREATED,
    response_model=StandardResponse[RegisterResponse],
    summary="Register a new user account",
)
async def register(
    request_data: RegisterRequest,
    request: Request, 
    db: AsyncSession = Depends(get_db),
    _: None = Depends(RateLimiter("register")),
):
    service = AuthService(db)
    user_data = await service.register(
        email=request_data.email,
        password=request_data.password,
        full_name=request_data.full_name,
    )
    return StandardResponse.success(
        message="Registration successful. Please check your email to verify your account.",
        data=RegisterResponse(**user_data),
    )


@router.post(
    "/verify-email",
    status_code=status.HTTP_200_OK,
    response_model=StandardResponse,
    summary="Verify email address",
)
async def verify_email(
    request_data: VerifyEmailRequest,
    db: AsyncSession = Depends(get_db),
):
    service = AuthService(db)
    await service.verify_email(token=request_data.token)
    return StandardResponse.success(
        message="Email verified successfully. You can now log in."
    )


@router.post(
    "/resend-verification",
    status_code=status.HTTP_200_OK,
    response_model=StandardResponse,
    summary="Resend email verification link",
)
async def resend_verification(
    request_data: ResendVerificationRequest,
    request: Request, 
    db: AsyncSession = Depends(get_db),
    _: None = Depends(RateLimiter("resend_verification")),
):
    service = AuthService(db)
    await service.resend_verification(email=request_data.email)
    return StandardResponse.success(
        message=(
            "If an account with that email exists and is unverified, "
            "a new verification link has been sent."
        )
    )


@router.post(
    "/login",
    status_code=status.HTTP_200_OK,
    response_model=StandardResponse[LoginResponse],
    summary="Login with email and password",
)
async def login(
    request_data: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(RateLimiter("login")),
):
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    service = AuthService(db)
    login_data = await service.login(
        email=request_data.email,
        password=request_data.password,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    return StandardResponse.success(
        message="Login successful.",
        data=LoginResponse(**login_data),
    )


@router.post(
    "/refresh",
    status_code=status.HTTP_200_OK,
    response_model=StandardResponse[RefreshResponse],
    summary="Refresh access token",
    description=(
        "Exchange a valid refresh token for a new access token and "
        "new refresh token. The old refresh token is immediately invalidated. "
        "Store the new refresh token — the old one cannot be used again."
    ),
)
async def refresh_tokens(
    request_data: RefreshRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Token refresh endpoint.

    The client calls this when their access token expires (every 15 min).
    They send their refresh token and get a brand new token pair back.

    IMPORTANT: The client must save the NEW refresh token.
    Using the old one again triggers reuse detection.
    """
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    service = AuthService(db)
    token_data = await service.refresh_tokens(
        raw_refresh_token=request_data.refresh_token,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    return StandardResponse.success(
        message="Tokens refreshed successfully.",
        data=RefreshResponse(**token_data),
    )


@router.post(
    "/logout",
    status_code=status.HTTP_200_OK,
    response_model=StandardResponse,
    summary="Logout current session",
)
async def logout(
    request_data: LogoutRequest,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
):
    """
    Logout endpoint.

    Immediately invalidates the access token (via Redis blacklist)
    and revokes the refresh token (via DB flag).

    After this call:
    - The access token will be rejected even if not yet expired
    - The refresh token cannot be used to get new tokens
    - The session is marked inactive
    """
    if not credentials:
        return StandardResponse.success(message="Logged out successfully.")

    service = AuthService(db)
    await service.logout(
        access_token=credentials.credentials,
        refresh_token=request_data.refresh_token,
    )
    return StandardResponse.success(message="Logged out successfully.")


@router.post(
    "/logout-all",
    status_code=status.HTTP_200_OK,
    response_model=StandardResponse,
    summary="Logout from all devices",
)
async def logout_all(
    current_user: CurrentUser,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
):
    """
    Logout from ALL devices simultaneously.

    Revokes every refresh token and deactivates every session
    for this user — regardless of which device they were created on.
    """
    access_token = credentials.credentials if credentials else ""

    service = AuthService(db)
    await service.logout_all(
        user_id=current_user.id,
        access_token=access_token,
    )
    return StandardResponse.success(
        message="Logged out from all devices successfully."
    )