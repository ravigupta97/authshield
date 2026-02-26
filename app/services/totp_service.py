"""

Two-Factor Authentication using TOTP (Time-based One-Time Password).

HOW TOTP WORKS:
1. We generate a random secret key (base32 encoded)
2. The secret is shared with the user via QR code
3. The authenticator app uses the secret + current time
   to generate a 6-digit code that changes every 30 seconds
4. On verification, we compute the expected code using the
   same secret + current time and compare

The magic: both sides (our server and the user's phone) compute
the same code from the same secret + same time — no network
communication needed after setup.

SECURITY:
- Secret is stored encrypted in the DB (totp_secret column)
- We allow a 1-interval window (±30 seconds) for clock skew
- Each code can only be used once (enforced by the 30s window)
- Temp tokens for 2FA login are stored in Redis with 5min TTL

LIBRARIES:
- pyotp: generates and verifies TOTP codes
- qrcode: generates QR code images
- Pillow: required by qrcode for PNG output
"""

import base64
import io
import uuid

import pyotp
import qrcode
import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.exceptions import (
    TwoFactorAlreadyEnabledError,
    TwoFactorInvalidError,
    TwoFactorNotEnabledError,
    TwoFactorRequiredError,
    UserNotFoundError,
)
from app.core.security import generate_secure_token
from app.db.redis import get_redis
from app.repositories.user_repository import UserRepository
from app.services.token_service import TokenService

log = structlog.get_logger()

# Redis key for 2FA temp tokens (issued when 2FA required at login)
TWO_FA_TEMP_KEY = "2fa_temp:{temp_token}"
TWO_FA_TEMP_TTL = 300  # 5 minutes

# Redis key for pending 2FA setup (secret before user confirms)
TWO_FA_PENDING_KEY = "2fa_pending:{user_id}"
TWO_FA_PENDING_TTL = 600  # 10 minutes to complete setup


class TOTPService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.user_repo = UserRepository(db)
        self.token_service = TokenService(db)

    # ── Enable 2FA ────────────────────────────────────────────────

    async def initiate_2fa_setup(self, user_id: uuid.UUID) -> dict:
        """
        Start the 2FA setup process.

        Generates a TOTP secret, creates a QR code, and stores
        the secret in Redis temporarily. The secret is NOT saved
        to the DB yet — only after the user confirms with a valid
        code (prove they scanned it correctly).

        Returns:
        - secret: the raw base32 secret (for manual entry)
        - qr_code: base64-encoded PNG QR code image
        - The user scans this with their authenticator app
        """
        user = await self.user_repo.get_by_id(user_id)
        if not user:
            raise UserNotFoundError()

        if user.is_2fa_enabled:
            raise TwoFactorAlreadyEnabledError()

        # Generate a cryptographically secure TOTP secret
        # base32 encoded, 32 bytes = 256 bits of entropy
        secret = pyotp.random_base32()

        # Build the TOTP URI — this is what the QR code encodes
        # Format: otpauth://totp/{issuer}:{email}?secret={secret}&issuer={issuer}
        # Authenticator apps parse this URI from the QR code
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=user.email,
            issuer_name=settings.app_name,
        )

        # Generate QR code image
        qr_image = qrcode.make(totp_uri)

        # Convert to base64 PNG for easy transmission in JSON
        buffer = io.BytesIO()
        qr_image.save(buffer, format="PNG")
        qr_base64 = base64.b64encode(buffer.getvalue()).decode("utf-8")

        # Store secret in Redis temporarily (not in DB yet)
        # Key: 2fa_pending:{user_id} → secret
        # TTL: 10 minutes to complete setup
        redis = get_redis()
        await redis.setex(
            TWO_FA_PENDING_KEY.format(user_id=str(user_id)),
            TWO_FA_PENDING_TTL,
            secret,
        )

        log.info("2FA setup initiated", user_id=str(user_id))

        return {
            "secret": secret,          # For manual entry in authenticator app
            "qr_code": qr_base64,      # Base64 PNG — render as <img> in frontend
            "qr_uri": totp_uri,        # The raw URI (alternative to QR image)
        }

    async def confirm_2fa_setup(
        self,
        user_id: uuid.UUID,
        totp_code: str,
    ) -> dict:
        """
        Confirm 2FA setup by verifying the user scanned the QR code.

        The user provides a 6-digit code from their authenticator app.
        We verify it against the pending secret in Redis.
        If valid, we save the secret to DB and enable 2FA.

        WHY require confirmation?
        If we saved the secret without verification, the user might
        have scanned incorrectly. They'd enable 2FA and immediately
        be locked out. Confirmation proves they have a working setup.
        """
        redis = get_redis()
        pending_key = TWO_FA_PENDING_KEY.format(user_id=str(user_id))

        # Get the pending secret from Redis
        secret = await redis.get(pending_key)
        if not secret:
            raise TwoFactorInvalidError(
                message=(
                    "No pending 2FA setup found. "
                    "Please initiate setup again."
                )
            )

        # Verify the TOTP code against the pending secret
        # valid_window=1 allows ±1 interval (±30 seconds) for clock skew
        totp = pyotp.TOTP(secret)
        if not totp.verify(totp_code, valid_window=1):
            raise TwoFactorInvalidError()

        # Code is valid — save secret to DB and enable 2FA
        user = await self.user_repo.get_by_id(user_id)
        if not user:
            raise UserNotFoundError()

        await self.user_repo.update(
            user,
            totp_secret=secret,
            is_2fa_enabled=True,
        )

        # Clean up pending secret from Redis
        await redis.delete(pending_key)

        await self.db.commit()

        log.info("2FA enabled", user_id=str(user_id))

        # Return backup info for the user to save
        return {
            "message": "Two-factor authentication has been enabled.",
            "recovery_hint": (
                "Keep your authenticator app safe. "
                "If you lose access, contact support."
            ),
        }

    # ── Verify 2FA at Login ───────────────────────────────────────

    async def issue_2fa_temp_token(self, user_id: uuid.UUID) -> str:
        """
        Issue a temporary token after password verification when 2FA is enabled.

        This temp_token is returned to the client instead of JWT tokens.
        The client must then call verify_2fa_login() with this token
        + a valid TOTP code to get the actual JWT tokens.

        The temp_token proves the user passed password verification
        without giving them full authentication yet.
        """
        temp_token = generate_secure_token(32)
        redis = get_redis()

        await redis.setex(
            TWO_FA_TEMP_KEY.format(temp_token=temp_token),
            TWO_FA_TEMP_TTL,
            str(user_id),
        )

        return temp_token

    async def verify_2fa_login(
        self,
        temp_token: str,
        totp_code: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> dict:
        """
        Complete login by verifying the TOTP code.

        Called after the user provides their 6-digit code
        in response to the 2FA required error from login.

        Flow:
        1. Look up temp_token in Redis → get user_id
        2. Load user and their TOTP secret
        3. Verify the TOTP code
        4. Delete temp_token (single-use)
        5. Issue JWT tokens
        """
        redis = get_redis()
        temp_key = TWO_FA_TEMP_KEY.format(temp_token=temp_token)

        # Step 1: Look up temp token
        user_id_str = await redis.get(temp_key)
        if not user_id_str:
            raise TwoFactorInvalidError(
                message=(
                    "Invalid or expired 2FA session. "
                    "Please log in again."
                )
            )

        # Step 2: Load user
        user = await self.user_repo.get_by_id(uuid.UUID(user_id_str))
        if not user or not user.is_active:
            raise TwoFactorInvalidError()

        # Step 3: Verify TOTP code
        if not user.totp_secret:
            raise TwoFactorInvalidError()

        totp = pyotp.TOTP(user.totp_secret)
        if not totp.verify(totp_code, valid_window=1):
            raise TwoFactorInvalidError()

        # Step 4: Delete temp token (single-use)
        await redis.delete(temp_key)

        # Step 5: Issue JWT tokens
        from app.services.auth_service import AuthService
        device_info = self._parse_device_info(user_agent)
        token_data = await self.token_service.create_tokens_for_user(
            user=user,
            ip_address=ip_address,
            user_agent=user_agent,
            device_info=device_info,
        )

        await self.db.commit()

        log.info(
            "2FA login verified",
            user_id=str(user.id),
            email=user.email,
        )

        return {
            "access_token": token_data["access_token"],
            "refresh_token": token_data["refresh_token"],
            "token_type": token_data["token_type"],
            "expires_in": token_data["expires_in"],
            "user": {
                "id": user.id,
                "email": user.email,
                "full_name": user.full_name,
                "roles": user.role_names,
                "is_2fa_enabled": user.is_2fa_enabled,
            },
        }

    # ── Disable 2FA ───────────────────────────────────────────────

    async def disable_2fa(
        self,
        user_id: uuid.UUID,
        totp_code: str,
    ) -> None:
        """
        Disable 2FA on the account.

        Requires a valid TOTP code to confirm the user still has
        access to their authenticator app. This prevents an attacker
        with a stolen session from disabling 2FA silently.
        """
        user = await self.user_repo.get_by_id(user_id)
        if not user:
            raise UserNotFoundError()

        if not user.is_2fa_enabled:
            raise TwoFactorNotEnabledError()

        # Verify they still have their authenticator app
        if not user.totp_secret:
            raise TwoFactorInvalidError()

        totp = pyotp.TOTP(user.totp_secret)
        if not totp.verify(totp_code, valid_window=1):
            raise TwoFactorInvalidError()

        # Disable 2FA and clear the secret
        await self.user_repo.update(
            user,
            is_2fa_enabled=False,
            totp_secret=None,
        )

        await self.db.commit()

        log.info("2FA disabled", user_id=str(user_id))

    # ── Helpers ───────────────────────────────────────────────────

    def _parse_device_info(self, user_agent: str | None) -> str | None:
        if not user_agent:
            return None
        ua = user_agent.lower()
        os = (
            "Windows" if "windows" in ua else
            "macOS" if "macintosh" in ua else
            "iPhone" if "iphone" in ua else
            "Android" if "android" in ua else
            "Linux" if "linux" in ua else
            "Unknown OS"
        )
        browser = (
            "Edge" if "edg/" in ua else
            "Chrome" if "chrome" in ua and "chromium" not in ua else
            "Firefox" if "firefox" in ua else
            "Safari" if "safari" in ua and "chrome" not in ua else
            "Unknown Browser"
        )
        return f"{browser} on {os}"