
"""

Password management endpoints.
Separated from auth.py to keep files focused and manageable.
"""

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.rate_limiter import RateLimiter
from app.api.v1.dependencies import CurrentUser, get_db
from app.schemas.auth import (
    ChangePasswordRequest,
    ForgotPasswordRequest,
    ResetPasswordRequest,
)
from app.schemas.common import StandardResponse
from app.services.password_service import PasswordService

router = APIRouter()


@router.post(
    "/forgot-password",
    status_code=status.HTTP_200_OK,
    response_model=StandardResponse,
    summary="Request a password reset link",
    description=(
        "Sends a password reset link to the provided email address. "
        "Always returns the same response regardless of whether the "
        "email exists — this prevents email enumeration attacks."
    ),
)
async def forgot_password(
    request_data: ForgotPasswordRequest,
    request: Request,  
    db: AsyncSession = Depends(get_db),
    _: None = Depends(RateLimiter("forgot_password")),
):
    """
    Forgot password endpoint.

    No authentication required — the user can't login.
    Rate limited (configured in middleware) to prevent abuse.

    We always return success. The client never learns whether
    the email exists in our system.
    """
    service = PasswordService(db)
    await service.forgot_password(email=request_data.email)

    return StandardResponse.success(
        message=(
            "If an account with that email address exists, "
            "a password reset link has been sent. "
            "Please check your inbox (and spam folder)."
        )
    )


@router.post(
    "/reset-password",
    status_code=status.HTTP_200_OK,
    response_model=StandardResponse,
    summary="Reset password using token from email",
    description=(
        "Resets the user's password using the token from the reset email. "
        "Token is single-use and expires in 1 hour. "
        "All existing sessions are revoked after a successful reset."
    ),
)
async def reset_password(
    request_data: ResetPasswordRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Reset password endpoint.

    The token comes from the URL parameter in the reset email link:
    /reset-password?token=<token_here>

    Frontend extracts the token from the URL and sends it here.
    """
    service = PasswordService(db)
    await service.reset_password(
        raw_token=request_data.token,
        new_password=request_data.new_password,
    )

    return StandardResponse.success(
        message=(
            "Password reset successful. "
            "All existing sessions have been logged out. "
            "Please log in with your new password."
        )
    )


@router.post(
    "/change-password",
    status_code=status.HTTP_200_OK,
    response_model=StandardResponse,
    summary="Change password (authenticated)",
    description=(
        "Changes the password for the currently authenticated user. "
        "Requires the current password for verification. "
        "All other sessions are revoked after a successful change."
    ),
)
async def change_password(
    request_data: ChangePasswordRequest,
    current_user: CurrentUser,      # Must be logged in
    db: AsyncSession = Depends(get_db),
):
    """
    Change password endpoint.

    Requires authentication — user must be logged in.
    Also requires their current password as a second check.
    This prevents an attacker with a stolen session from
    silently changing the password.
    """
    service = PasswordService(db)
    await service.change_password(
        user_id=current_user.id,
        current_password=request_data.current_password,
        new_password=request_data.new_password,
    )

    return StandardResponse.success(
        message=(
            "Password changed successfully. "
            "Other active sessions have been logged out."
        )
    )