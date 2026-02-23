"""

Business logic for authentication operations.

This layer:
- Enforces business rules ("email must be unique", "must be verified to login")
- Orchestrates multiple repositories and utilities
- Knows NOTHING about HTTP (no Request/Response objects)
- Knows NOTHING about raw SQL (uses repositories)
"""

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import (
    generate_secure_token,
    hash_password,
)
from app.core.exceptions import EmailAlreadyRegisteredError
from app.db.redis import get_redis
from app.repositories.user_repository import UserRepository
from app.services.email_service import email_service
from app.config import settings

log = structlog.get_logger()

# Redis key templates — centralized so they're consistent everywhere
VERIFY_TOKEN_KEY = "email_verify:{token}"
VERIFY_TOKEN_TTL = 86400  # 24 hours in seconds


class AuthService:
    """
    Handles user registration, login, logout, and email verification.
    Instantiated per-request with a database session.
    """

    def __init__(self, db: AsyncSession):
        self.db = db
        self.user_repo = UserRepository(db)

    async def register(
        self,
        email: str,
        password: str,
        full_name: str,
    ) -> dict:
        """
        Register a new user with email and password.

        Flow:
        1. Check email isn't already taken
        2. Hash the password
        3. Create the user (unverified)
        4. Assign the default 'user' role
        5. Generate email verification token
        6. Store token in Redis (with 24hr expiry)
        7. Send verification email
        8. Commit everything to DB
        9. Return user data

        WHY store verification token in Redis instead of DB?
        - It's temporary data (expires in 24 hours)
        - Redis handles TTL automatically (self-cleaning)
        - Faster lookup than a DB query
        - No need for a separate verification_tokens table
        """

        # Step 1: Check for duplicate email
        if await self.user_repo.email_exists(email):
            raise EmailAlreadyRegisteredError()

        # Step 2: Hash password
        # This takes ~250ms intentionally (bcrypt work factor)
        password_hash = hash_password(password)

        # Step 3: Create user (unverified by default)
        user = await self.user_repo.create(
            email=email,
            full_name=full_name,
            password_hash=password_hash,
            is_verified=False,
        )

        # Step 4: Assign default 'user' role
        await self.user_repo.assign_role(user, "user")

        # Step 5: Generate verification token
        # generate_secure_token() uses os.urandom() — cryptographically safe
        token = generate_secure_token(64)

        # Step 6: Store token in Redis
        # Key: email_verify:{token} → Value: user_id (as string)
        # TTL: 86400 seconds = 24 hours
        redis = get_redis()
        await redis.setex(
            VERIFY_TOKEN_KEY.format(token=token),
            VERIFY_TOKEN_TTL,
            str(user.id),
        )

        # Step 7: Commit to database BEFORE sending email
        # WHY? If email fails, the user still exists and can request
        # a new verification email. If we committed after email and
        # email succeeded but commit failed — user gets a broken link.
        await self.db.commit()
        await self.db.refresh(user)

        # Step 8: Send verification email (non-blocking, won't raise)
        await email_service.send_verification_email(
            to_email=user.email,
            full_name=user.full_name,
            token=token,
        )

        log.info(
            "User registered",
            user_id=str(user.id),
            email=user.email,
        )

        return {
            "user_id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "is_verified": user.is_verified,
            "created_at": user.created_at,
        }

    async def verify_email(self, token: str) -> None:
        """
        Verify a user's email address using the token from their email.

        Flow:
        1. Look up token in Redis
        2. Get the user_id stored with the token
        3. Mark user as verified in DB
        4. Delete the token from Redis (single-use)
        """
        redis = get_redis()
        key = VERIFY_TOKEN_KEY.format(token=token)

        # Step 1 & 2: Look up token
        user_id = await redis.get(key)

        if not user_id:
            from app.core.exceptions import InvalidVerificationTokenError
            raise InvalidVerificationTokenError()

        # Step 3: Get user and mark verified
        import uuid
        user = await self.user_repo.get_by_id(uuid.UUID(user_id))

        if not user:
            from app.core.exceptions import InvalidVerificationTokenError
            raise InvalidVerificationTokenError()

        await self.user_repo.update(user, is_verified=True)

        # Step 4: Delete token (single-use — can't verify twice with same link)
        await redis.delete(key)

        await self.db.commit()

        log.info("Email verified", user_id=str(user.id), email=user.email)

    async def resend_verification(self, email: str) -> None:
        """
        Resend the email verification link.

        SECURITY: We return the same response whether the email
        exists or not. This prevents email enumeration attacks
        (attacker can't probe which emails are registered).
        """
        user = await self.user_repo.get_by_email(email)

        # If user doesn't exist or is already verified, silently do nothing
        if not user or user.is_verified:
            return

        # Generate new token
        token = generate_secure_token(64)
        redis = get_redis()

        await redis.setex(
            VERIFY_TOKEN_KEY.format(token=token),
            VERIFY_TOKEN_TTL,
            str(user.id),
        )

        await email_service.send_verification_email(
            to_email=user.email,
            full_name=user.full_name,
            token=token,
        )

        log.info("Verification email resent", email=email)