"""
app/api/v1/endpoints/auth.py

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
    description=(
        "Creates a new user account with email and password. "
        "A verification email is sent to the provided address. "
        "The account cannot be used until the email is verified."
    ),
)
async def register(
    request_data: RegisterRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Register endpoint.

    FastAPI automatically:
    - Parses the JSON body into RegisterRequest
    - Runs Pydantic validators (email format, password strength)
    - Returns 422 if validation fails (before we even get here)

    We just call the service and format the response.
    """
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
    """
    Verify a user's email with the token from their verification email.
    Token is single-use and expires in 24 hours.
    """
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
    """
    Resend the verification email.
    Always returns the same response to prevent email enumeration.
    """
    service = AuthService(db)
    await service.resend_verification(email=request_data.email)

    return StandardResponse.success(
        message=(
            "If an account with that email exists and is unverified, "
            "a new verification link has been sent."
        )
    )