"""

Database operations for refresh tokens.
Handles creation, lookup by raw token, rotation, and revocation.
"""

import hashlib
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.refresh_token import RefreshToken


class TokenRepository:
    """
    All database operations for RefreshToken.

    WHY hash the token before storing?
    If an attacker gets database access, they see hashes — not usable
    tokens. Same principle as password hashing.

    We use SHA-256 here (not bcrypt) because:
    - Refresh tokens are already random and high-entropy (64 bytes)
    - SHA-256 is fast — we don't need bcrypt's deliberate slowness
    - bcrypt has a 72-byte input limit (our tokens are longer)
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    @staticmethod
    def _hash_token(raw_token: str) -> str:
        """
        Hash a raw token using SHA-256.
        Deterministic — same input always produces same hash.
        Used for both storage and lookup.
        """
        return hashlib.sha256(raw_token.encode()).hexdigest()

    async def create(
        self,
        user_id: uuid.UUID,
        raw_token: str,
        family_id: uuid.UUID | None = None,
    ) -> RefreshToken:
        """
        Store a new refresh token.

        family_id: Pass None for a brand new login (creates new family).
                   Pass existing family_id when rotating (keeps family chain).
        """
        expires_at = datetime.now(timezone.utc) + timedelta(
            days=settings.refresh_token_expire_days
        )

        token = RefreshToken(
            user_id=user_id,
            token_hash=self._hash_token(raw_token),
            family_id=family_id or uuid.uuid4(),  # New family for new logins
            is_used=False,
            is_revoked=False,
            expires_at=expires_at,
        )
        self.db.add(token)
        await self.db.flush()
        return token

    async def get_by_raw_token(self, raw_token: str) -> RefreshToken | None:
        """
        Look up a refresh token by the raw token string.
        Hashes it first, then queries by hash.
        """
        token_hash = self._hash_token(raw_token)
        result = await self.db.execute(
            select(RefreshToken).where(RefreshToken.token_hash == token_hash)
        )
        return result.scalar_one_or_none()

    async def mark_as_used(
        self,
        token: RefreshToken,
        replaced_by_id: uuid.UUID,
    ) -> None:
        """
        Mark a token as used during rotation.
        Records which token replaced it (for chain tracking).
        """
        token.is_used = True
        token.replaced_by_id = replaced_by_id
        await self.db.flush()

    async def revoke_token(self, token: RefreshToken) -> None:
        """Revoke a single token (logout)."""
        token.is_revoked = True
        await self.db.flush()

    async def revoke_all_user_tokens(self, user_id: uuid.UUID) -> None:
        """
        Revoke ALL refresh tokens for a user.
        Used when:
        - User logs out from all devices
        - Reuse detected (security event)
        - Password reset
        - Admin deactivates account
        """
        await self.db.execute(
            update(RefreshToken)
            .where(RefreshToken.user_id == user_id)
            .where(RefreshToken.is_revoked == False)  # noqa: E712
            .values(is_revoked=True)
        )

    async def revoke_token_family(self, family_id: uuid.UUID) -> None:
        """
        Revoke all tokens in a family.
        Called when reuse is detected on any token in the family.
        This kills both the attacker's current token AND the
        legitimate user's current token — forcing re-login.
        """
        await self.db.execute(
            update(RefreshToken)
            .where(RefreshToken.family_id == family_id)
            .values(is_revoked=True)
        )

    async def is_token_valid(self, token: RefreshToken) -> bool:
        """
        Check if a refresh token is currently usable.
        A token is valid only if ALL conditions are true.
        """
        now = datetime.now(timezone.utc)
        return (
            not token.is_used
            and not token.is_revoked
            and token.expires_at > now
        )
    
    async def get_by_session(
        self,
        refresh_token_id: uuid.UUID,
    ) -> RefreshToken | None:
        """
        Fetch a refresh token by its primary key (ID).
        Used when revoking a session — we have the token ID
        from the session record and need the token object.
        """
        result = await self.db.execute(
            select(RefreshToken).where(RefreshToken.id == refresh_token_id)
        )
        return result.scalar_one_or_none()