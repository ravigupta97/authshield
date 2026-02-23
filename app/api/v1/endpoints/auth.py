"""

HTTP layer for authentication endpoints.
Responsibilities:
- Parse HTTP requests
- Call the appropriate service method
- Return properly formatted HTTP responses
- Nothing else. No business logic here.
"""

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies import get_db
from app.schemas.auth import (
    LoginRequest,
    LoginResponse,
    RegisterRequest,
    RegisterResponse,
    ResendVerificationRequest,
    VerifyEmailRequest,
)
from app.schemas.common import StandardResponse
from app.services.auth_service import AuthService

router = APIRouter()


@router.post(
    "/register",
    status_code=status.HTTP_201_CREATED,
    response_model=StandardResponse[RegisterResponse],
    summary="Register a new user account",
)
async def register(
    request_data: RegisterRequest,
    db: AsyncSession = Depends(get_db),
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
    db: AsyncSession = Depends(get_db),
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
    description=(
        "Authenticates a user and returns a JWT access token (15 min) "
        "and a refresh token (7 days). The account must be verified first."
    ),
)
async def login(
    request_data: LoginRequest,
    request: Request,          # FastAPI injects the raw request
    db: AsyncSession = Depends(get_db),
):
    """
    Login endpoint.

    We extract IP and User-Agent from the request here (HTTP concern),
    then pass them to the service (which doesn't know about HTTP).
    """
    # Extract client info for session tracking and audit log
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