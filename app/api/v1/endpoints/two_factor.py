"""

Two-Factor Authentication endpoints.

FLOW SUMMARY:

SETUP (3 steps):
1. POST /2fa/enable   → get QR code
2. User scans QR code in authenticator app
3. POST /2fa/confirm  → send 6-digit code to confirm setup

LOGIN WITH 2FA:
1. POST /auth/login   → returns 403 + temp_token (if 2FA enabled)
2. POST /2fa/verify   → send temp_token + totp_code → get JWT tokens

DISABLE:
1. POST /2fa/disable  → send current totp_code to confirm identity
"""

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.rate_limiter import RateLimiter
from app.api.v1.dependencies import CurrentUser, get_db
from app.schemas.common import StandardResponse
from app.schemas.two_factor import (
    TwoFactorConfirmRequest,
    TwoFactorDisableRequest,
    TwoFactorLoginResponse,
    TwoFactorSetupResponse,
    TwoFactorVerifyRequest,
)
from app.services.totp_service import TOTPService

router = APIRouter()


@router.post(
    "/enable",
    response_model=StandardResponse[TwoFactorSetupResponse],
    summary="Initiate 2FA setup",
    description=(
        "Generates a TOTP secret and QR code. "
        "Scan the QR code with your authenticator app "
        "(Google Authenticator, Authy, etc.), then call "
        "POST /2fa/confirm with a valid code to activate 2FA."
    ),
)
async def enable_2fa(
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
):
    """
    Start 2FA setup. Returns QR code to scan.
    2FA is NOT enabled until /2fa/confirm is called successfully.
    """
    service = TOTPService(db)
    setup_data = await service.initiate_2fa_setup(user_id=current_user.id)

    return StandardResponse.success(
        message=(
            "Scan the QR code with your authenticator app, "
            "then confirm setup with POST /2fa/confirm."
        ),
        data=TwoFactorSetupResponse(**setup_data),
    )


@router.post(
    "/confirm",
    response_model=StandardResponse,
    summary="Confirm 2FA setup",
    description=(
        "Verifies the user successfully scanned the QR code "
        "by checking a valid 6-digit code from their app. "
        "2FA is activated only after this step succeeds."
    ),
)
async def confirm_2fa(
    request_data: TwoFactorConfirmRequest,
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
):
    """
    Confirm 2FA setup by providing a valid code from the authenticator app.
    """
    service = TOTPService(db)
    result = await service.confirm_2fa_setup(
        user_id=current_user.id,
        totp_code=request_data.totp_code,
    )

    return StandardResponse.success(
        message=result["message"],
    )


@router.post(
    "/verify",
    response_model=StandardResponse[TwoFactorLoginResponse],
    summary="Complete login with 2FA code",
    description=(
        "Complete the login process when 2FA is enabled. "
        "Send the temp_token from the login response "
        "along with the 6-digit code from your authenticator app."
    ),
)
async def verify_2fa_login(
    request_data: TwoFactorVerifyRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(RateLimiter("two_fa_verify")),
):
    """
    Complete 2FA login.

    Called after POST /auth/login returns AUTH_2FA_REQUIRED.
    The client sends the temp_token from that response + the
    current 6-digit code from their authenticator app.
    """
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    service = TOTPService(db)
    token_data = await service.verify_2fa_login(
        temp_token=request_data.temp_token,
        totp_code=request_data.totp_code,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    return StandardResponse.success(
        message="Login successful.",
        data=TwoFactorLoginResponse(**token_data),
    )


@router.post(
    "/disable",
    response_model=StandardResponse,
    summary="Disable 2FA",
    description=(
        "Disables two-factor authentication. "
        "Requires a valid TOTP code from your authenticator app "
        "to confirm you still have access before disabling."
    ),
)
async def disable_2fa(
    request_data: TwoFactorDisableRequest,
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
):
    """
    Disable 2FA. Requires current TOTP code for confirmation.
    """
    service = TOTPService(db)
    await service.disable_2fa(
        user_id=current_user.id,
        totp_code=request_data.totp_code,
    )

    return StandardResponse.success(
        message="Two-factor authentication has been disabled.",
    )