"""

All database operations for the User model.

REPOSITORY PATTERN: This layer knows about SQL/ORM.
It knows NOTHING about HTTP, business rules, or tokens.
Service layer calls these methods. Services never write raw queries.

WHY THIS SEPARATION?
If you switch from PostgreSQL to MongoDB, you only rewrite this file.
The service layer stays identical.
"""

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.user import User
from app.models.role import Role
import structlog
log = structlog.get_logger()

class UserRepository:
    """
    Encapsulates all User-related database operations.

    Receives an AsyncSession via constructor injection.
    This makes it easy to test — just pass a mock session.
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    async def create(
        self,
        email: str,
        full_name: str,
        password_hash: str | None = None,
        oauth_provider: str | None = None,
        oauth_id: str | None = None,
        avatar_url: str | None = None,
        is_verified: bool = False,
    ) -> User:
        """
        Create a new user record.
        After flush, eagerly load the roles relationship so it's
        available in memory without triggering a lazy load later.
        """
        user = User(
            email=email.lower().strip(),  # Normalize email
            full_name=full_name.strip(),
            password_hash=password_hash,
            oauth_provider=oauth_provider,
            oauth_id=oauth_id,
            avatar_url=avatar_url,
            is_verified=is_verified,
        )
        self.db.add(user)
        await self.db.flush()  # Assigns the UUID without committing

        # Explicitly refresh with roles loaded
        # This runs: SELECT * FROM users WHERE id=? + SELECT roles...
        # Prevents the lazy-load error when we access user.roles later
        await self.db.refresh(user, attribute_names=["roles"])
        return user

    async def get_by_id(self, user_id: uuid.UUID) -> User | None:
        """Fetch user by primary key. Returns None if not found."""
        result = await self.db.execute(
            select(User)
            .where(User.id == user_id)
            .options(selectinload(User.roles))  # Eagerly load roles
        )
        return result.scalar_one_or_none()

    async def get_by_email(self, email: str) -> User | None:
        """
        Fetch user by email address.
        Used on every login — the index on email makes this fast.
        """
        result = await self.db.execute(
            select(User)
            .where(User.email == email.lower().strip())
            .options(selectinload(User.roles))
        )
        return result.scalar_one_or_none()

    async def get_by_oauth(
        self,
        provider: str,
        oauth_id: str,
    ) -> User | None:
        """
        Fetch user by OAuth provider + provider's user ID.
        Used during OAuth login to find returning OAuth users.
        """
        result = await self.db.execute(
            select(User)
            .where(User.oauth_provider == provider)
            .where(User.oauth_id == oauth_id)
            .options(selectinload(User.roles))
        )
        return result.scalar_one_or_none()

    async def email_exists(self, email: str) -> bool:
        """
        Check if an email is already registered.
        Faster than get_by_email() because it only checks existence.
        """
        result = await self.db.execute(
            select(User.id).where(User.email == email.lower().strip())
        )
        return result.scalar_one_or_none() is not None

    async def assign_role(self, user: User, role_name: str) -> None:
        """
        Assign a role to a user by role name.
        Checks existing roles using the already-loaded relationship
        to avoid triggering an implicit lazy load.
        """
        result = await self.db.execute(
            select(Role).where(Role.name == role_name)
        )
        role = result.scalar_one_or_none()
        if role is None:
            log.warning("Role not found during assignment", role_name=role_name)
            return

        # user.roles is already loaded (we called refresh with attribute_names)
        # so this comparison is safe — no implicit IO
        current_role_ids = [r.id for r in user.roles]
        if role.id not in current_role_ids:
            user.roles.append(role)
            await self.db.flush()

    async def update(self, user: User, **kwargs) -> User:
        """
        Update user fields.
        Accepts any User column as keyword argument.
        """
        for key, value in kwargs.items():
            if hasattr(user, key):
                setattr(user, key, value)
        await self.db.flush()
        return user

    async def get_all(
        self,
        page: int = 1,
        limit: int = 20,
        search: str | None = None,
        is_active: bool | None = None,
    ) -> tuple[list[User], int]:
        """
        Paginated list of all users. Used by admin endpoints.
        Returns (list_of_users, total_count).
        """
        query = select(User).options(selectinload(User.roles))

        if search:
            query = query.where(
                User.email.ilike(f"%{search}%") |
                User.full_name.ilike(f"%{search}%")
            )

        if is_active is not None:
            query = query.where(User.is_active == is_active)

        # Get total count
        count_result = await self.db.execute(
            select(User.id)
            .where(query.whereclause)
            if query.whereclause is not None
            else select(User.id)
        )
        total = len(count_result.fetchall())

        # Apply pagination
        query = query.offset((page - 1) * limit).limit(limit)
        result = await self.db.execute(query)

        return result.scalars().all(), total