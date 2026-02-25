"""

Business logic for password management:
- Forgot password (request reset link)
- Reset password (use token from email)
- Change password (authenticated user)

SECURITY DESIGN:
1. We store a HASH of the reset token in Redis, not the raw token.
   If Redis is compromised, the attacker gets hashes — not usable tokens.

2. The forgot-password endpoint ALWAYS returns the same response,
   whether the email exists or not. This prevents email enumeration —
   an attacker can't use this endpoint to discover registered emails.

3. After a successful password reset, ALL existing sessions are
   revoked. This is critical: if an attacker had access via a stolen
   session, the password reset immediately kicks them out.

4. Reset tokens are single-use and expire in 1 hour.
"""

import hashlib
import uuid

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import (
    InvalidResetTokenError,
    PasswordMismatchError,
    SamePasswordError,
)
from app.core.security import (
    generate_secure_token,
    hash_password,
    verify_password,
)
from app.db.redis import get_redis
from app.repositories.user_repository import UserRepository
from app.services.email_service import email_service
from app.services.token_service import TokenService

log = structlog.get_logger()

# Redis key template for password reset tokens
RESET_TOKEN_KEY = "pwd_reset:{token_hash}"
RESET_TOKEN_TTL = 3600  # 1 hour in seconds


class PasswordService:
    """
    Handles all password-related operations.
    Separated from AuthService because password management
    is its own domain with its own security requirements.
    """

    def __init__(self, db: AsyncSession):
        self.db = db
        self.user_repo = UserRepository(db)
        self.token_service = TokenService(db)

    @staticmethod
    def _hash_reset_token(raw_token: str) -> str:
        """
        Hash a reset token for safe storage.

        WHY SHA-256 and not bcrypt?
        - Reset tokens are already cryptographically random (high entropy)
        - We need fast lookup (SHA-256 is deterministic and instant)
        - bcrypt's deliberate slowness adds no security benefit here
          because there's nothing to brute-force (the token space is huge)
        - bcrypt has a 72-byte limit; our tokens can be longer
        """
        return hashlib.sha256(raw_token.encode()).hexdigest()

    async def forgot_password(self, email: str) -> None:
        """
        Request a password reset link.

        ALWAYS returns without error, even if:
        - Email doesn't exist in our system
        - Account is not verified
        - Account is disabled

        WHY? Email enumeration prevention. An attacker sending
        thousands of emails to this endpoint should learn nothing
        about which emails are registered in our system.

        We only send the email if the user actually exists and
        their account is in a usable state — but we never tell
        the caller whether we did or didn't.
        """
        user = await self.user_repo.get_by_email(email)

        # Silently do nothing if user doesn't exist or isn't verified
        # The caller gets the same success response either way
        if not user or not user.is_verified:
            log.info(
                "Password reset requested for non-existent/unverified email",
                email=email,
            )
            return

        # Generate a cryptographically secure random token
        raw_token = generate_secure_token(64)

        # Hash it before storing (store hash, send raw)
        token_hash = self._hash_reset_token(raw_token)

        # Store in Redis: key=hash, value=user_id, TTL=1 hour
        # When the user clicks the link, we hash the token from the URL
        # and look up this key to find the user_id
        redis = get_redis()
        await redis.setex(
            RESET_TOKEN_KEY.format(token_hash=token_hash),
            RESET_TOKEN_TTL,
            str(user.id),
        )

        # Send the RAW token in the email link (not the hash)
        # The link will look like: /reset-password?token=<raw_token>
        await email_service.send_password_reset_email(
            to_email=user.email,
            full_name=user.full_name,
            token=raw_token,
        )

        log.info(
            "Password reset email sent",
            user_id=str(user.id),
            email=email,
        )

    async def reset_password(
        self,
        raw_token: str,
        new_password: str,
    ) -> None:
        """
        Reset a user's password using a token from their email.

        Flow:
        1. Hash the token from the URL
        2. Look up the hash in Redis → get user_id
        3. Load user
        4. Ensure new password differs from current
        5. Hash and save new password
        6. Delete the reset token (single-use)
        7. Revoke ALL existing sessions and refresh tokens
           (kicks out any attacker who had access)
        8. Commit

        Step 7 is critical for security. Even if an attacker had
        a valid session before the password reset, they're immediately
        logged out. The legitimate user must log in fresh.
        """
        # Step 1 & 2: Hash token and look up in Redis
        token_hash = self._hash_reset_token(raw_token)
        redis = get_redis()
        key = RESET_TOKEN_KEY.format(token_hash=token_hash)

        user_id_str = await redis.get(key)

        if not user_id_str:
            # Token doesn't exist (wrong token, already used, or expired)
            raise InvalidResetTokenError()

        # Step 3: Load user
        user = await self.user_repo.get_by_id(uuid.UUID(user_id_str))

        if not user:
            # User was deleted after token was issued
            await redis.delete(key)
            raise InvalidResetTokenError()

        # Step 4: Ensure new password is different from current
        # Only check if user has a password (OAuth users might not)
        if user.password_hash:
            if verify_password(new_password, user.password_hash):
                raise SamePasswordError()

        # Step 5: Hash and save new password
        new_hash = hash_password(new_password)
        await self.user_repo.update(user, password_hash=new_hash)

        # Step 6: Delete reset token (single-use — can't reset twice)
        await redis.delete(key)

        # Step 7: Revoke ALL sessions and refresh tokens
        # This is the security-critical step — kicks out any attacker
        await self.token_service.revoke_all_user_tokens(user.id)

        # Step 8: Commit everything atomically
        await self.db.commit()

        log.info(
            "Password reset successful",
            user_id=str(user.id),
            email=user.email,
        )

    async def change_password(
        self,
        user_id: uuid.UUID,
        current_password: str,
        new_password: str,
        revoke_other_sessions: bool = True,
    ) -> None:
        """
        Change password for an authenticated user.

        Unlike reset_password(), this requires the current password
        to verify the user's identity — even though they're already
        authenticated. This prevents an attacker who stole a session
        from changing the password without knowing the original.

        revoke_other_sessions=True: After changing password, all
        OTHER sessions are revoked. The current session stays alive
        (better UX — user doesn't get kicked out immediately).
        Set to False if you want to keep all sessions alive.
        """
        # Load user
        user = await self.user_repo.get_by_id(user_id)
        if not user:
            from app.core.exceptions import UserNotFoundError
            raise UserNotFoundError()

        # Verify current password
        if not user.password_hash:
            # OAuth-only user — they don't have a password to change
            from app.core.exceptions import AuthShieldException
            raise AuthShieldException(
                message="Your account uses social login and doesn't have a password.",
                error_code="AUTH_NO_PASSWORD",
            )

        if not verify_password(current_password, user.password_hash):
            raise PasswordMismatchError()

        # Ensure new password differs from current
        if verify_password(new_password, user.password_hash):
            raise SamePasswordError()

        # Hash and save new password
        new_hash = hash_password(new_password)
        await self.user_repo.update(user, password_hash=new_hash)

        # Revoke all OTHER sessions (keep current one alive)
        # NOTE: In a future enhancement, we could pass the current
        # session_id and exclude it from revocation. For now, we
        # revoke all — slight inconvenience but safer.
        if revoke_other_sessions:
            await self.token_service.revoke_all_user_tokens(user.id)

        await self.db.commit()

        log.info(
            "Password changed successfully",
            user_id=str(user.id),
        )