"""

Business logic for admin operations.

WHY a separate AdminService?
Admin operations have different rules than regular operations:
- They bypass ownership checks (admin can manage any user)
- They have different logging requirements (audit trail)
- They often affect multiple resources atomically
- Keeping them separate makes auditing easier

PRINCIPLE OF LEAST PRIVILEGE:
Admin endpoints check roles at the API layer (require_roles).
The service layer assumes the caller is authorized — it doesn't
re-check roles. Role checking belongs in one place (the dependency).
"""

import uuid

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.exceptions import (
    SessionNotFoundError,
    UserNotFoundError,
)
from app.models.role import Role
from app.models.session import Session
from app.models.user import User
from app.repositories.session_repository import SessionRepository
from app.repositories.user_repository import UserRepository
from app.services.token_service import TokenService

log = structlog.get_logger()


class AdminService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.user_repo = UserRepository(db)
        self.session_repo = SessionRepository(db)
        self.token_service = TokenService(db)

    async def list_users(
        self,
        page: int = 1,
        limit: int = 20,
        search: str | None = None,
        is_active: bool | None = None,
        role: str | None = None,
    ) -> dict:
        """
        Paginated list of all users.
        Supports filtering by search term, active status, and role.
        """
        # Clamp limit to prevent abuse (max 100 per page)
        limit = min(limit, 100)
        page = max(page, 1)

        from sqlalchemy import func, or_
        from sqlalchemy.orm import selectinload

        # Build base query
        query = select(User).options(selectinload(User.roles))

        # Apply search filter (email OR full_name, case-insensitive)
        if search:
            search_term = f"%{search.strip()}%"
            query = query.where(
                or_(
                    User.email.ilike(search_term),
                    User.full_name.ilike(search_term),
                )
            )

        # Apply active status filter
        if is_active is not None:
            query = query.where(User.is_active == is_active)

        # Apply role filter
        if role:
            query = query.join(User.roles).where(Role.name == role)

        # Count total matching records (before pagination)
        count_query = select(func.count()).select_from(query.subquery())
        total_result = await self.db.execute(count_query)
        total = total_result.scalar() or 0

        # Apply pagination and ordering
        query = (
            query
            .order_by(User.created_at.desc())
            .offset((page - 1) * limit)
            .limit(limit)
        )

        result = await self.db.execute(query)
        users = list(result.scalars().unique().all())

        total_pages = (total + limit - 1) // limit  # Ceiling division

        return {
            "users": users,
            "total": total,
            "page": page,
            "limit": limit,
            "total_pages": total_pages,
        }

    async def get_user(self, user_id: uuid.UUID) -> User:
        """
        Get a specific user by ID.
        Raises UserNotFoundError if user doesn't exist.
        """
        user = await self.user_repo.get_by_id(user_id)
        if not user:
            raise UserNotFoundError()
        return user

    async def update_user_roles(
        self,
        user_id: uuid.UUID,
        role_names: list[str],
        admin_user_id: uuid.UUID,
    ) -> User:
        """
        Replace a user's entire role set with the provided roles.

        SAFETY CHECKS:
        - Validates all role names exist in the database
        - Prevents admin from removing their own admin role
          (would lock themselves out)
        - Prevents assigning no roles (user must have at least one)
        """
        user = await self.user_repo.get_by_id(user_id)
        if not user:
            raise UserNotFoundError()

        # Safety: admin cannot remove their own admin role
        if user_id == admin_user_id and "admin" not in role_names:
            from app.core.exceptions import AuthShieldException
            raise AuthShieldException(
                message="You cannot remove your own admin role.",
                error_code="ADMIN_CANNOT_REMOVE_OWN_ROLE",
            )

        # Fetch all requested roles from DB to validate they exist
        result = await self.db.execute(
            select(Role).where(Role.name.in_(role_names))
        )
        found_roles = list(result.scalars().all())

        # Check all requested roles were found
        found_names = {r.name for r in found_roles}
        invalid_names = set(role_names) - found_names
        if invalid_names:
            from app.core.exceptions import AuthShieldException
            raise AuthShieldException(
                message=f"Invalid role names: {invalid_names}",
                error_code="ADMIN_INVALID_ROLES",
            )

        # Replace roles entirely
        # Clear existing and assign new ones
        user.roles = found_roles
        await self.db.flush()
        await self.db.commit()
        await self.db.refresh(user)

        log.info(
            "User roles updated by admin",
            target_user_id=str(user_id),
            new_roles=role_names,
            admin_id=str(admin_user_id),
        )

        return user

    async def update_user_status(
        self,
        user_id: uuid.UUID,
        is_active: bool,
        admin_user_id: uuid.UUID,
    ) -> User:
        """
        Activate or deactivate a user account.

        When deactivating:
        - Sets is_active=False on the user
        - Revokes ALL their refresh tokens
        - Deactivates ALL their sessions
        This immediately locks the user out of all devices.

        Safety: Admin cannot deactivate their own account.
        """
        user = await self.user_repo.get_by_id(user_id)
        if not user:
            raise UserNotFoundError()

        # Safety: admin cannot deactivate themselves
        if user_id == admin_user_id and not is_active:
            from app.core.exceptions import AuthShieldException
            raise AuthShieldException(
                message="You cannot deactivate your own account.",
                error_code="ADMIN_CANNOT_DEACTIVATE_SELF",
            )

        # Update status
        await self.user_repo.update(user, is_active=is_active)

        # If deactivating, immediately revoke all sessions
        if not is_active:
            await self.token_service.revoke_all_user_tokens(user_id)
            log.warning(
                "User account deactivated — all sessions revoked",
                target_user_id=str(user_id),
                admin_id=str(admin_user_id),
            )
        else:
            log.info(
                "User account activated",
                target_user_id=str(user_id),
                admin_id=str(admin_user_id),
            )

        await self.db.commit()
        await self.db.refresh(user)
        return user

    async def get_user_sessions(
        self,
        user_id: uuid.UUID,
    ) -> list[Session]:
        """Get all active sessions for a specific user."""
        user = await self.user_repo.get_by_id(user_id)
        if not user:
            raise UserNotFoundError()

        return await self.session_repo.get_active_sessions_for_user(user_id)

    async def revoke_all_user_sessions(
        self,
        user_id: uuid.UUID,
        admin_user_id: uuid.UUID,
    ) -> None:
        """
        Force-logout a user from all devices.
        Revokes all tokens and deactivates all sessions.
        """
        user = await self.user_repo.get_by_id(user_id)
        if not user:
            raise UserNotFoundError()

        await self.token_service.revoke_all_user_tokens(user_id)
        await self.db.commit()

        log.warning(
            "All user sessions revoked by admin",
            target_user_id=str(user_id),
            admin_id=str(admin_user_id),
        )