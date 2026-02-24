"""

FastAPI dependency functions shared across all endpoints.

HOW FASTAPI DEPENDENCIES WORK:
When a route declares a parameter like:
    current_user: User = Depends(get_current_user)

FastAPI automatically:
1. Calls get_current_user() before the route handler runs
2. Passes its return value as the 'current_user' parameter
3. If get_current_user() raises an exception, the route never runs

This gives us a clean, reusable way to protect routes without
repeating auth logic in every single endpoint.
"""

from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import (
    InsufficientPermissionsError,
    TokenExpiredError,
    TokenInvalidError,
    TokenRevokedError,
)
from app.db.session import get_db
from app.models.user import User
from app.repositories.user_repository import UserRepository
from app.services.token_service import TokenService

# HTTPBearer extracts the token from the Authorization: Bearer <token> header.
# auto_error=False means it returns None instead of raising 403
# if the header is missing — we handle the error ourselves with
# a more descriptive message.
bearer_scheme = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: Annotated[
        HTTPAuthorizationCredentials | None,
        Depends(bearer_scheme),
    ],
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    Core authentication dependency.

    Extracts the JWT from the Authorization header, verifies it,
    checks the blacklist, loads the user from the database, and
    returns the User object.

    Usage in any protected endpoint:
        @router.get("/protected")
        async def my_route(
            current_user: User = Depends(get_current_user)
        ):
            return {"user_id": current_user.id}

    WHY load the user from DB instead of just trusting the JWT?
    The JWT contains user_id, email, roles. But what if:
    - Admin deactivated the user after the token was issued?
    - User was deleted?
    We need to verify the user still exists and is still active.
    Roles we trust from the JWT (they're refreshed on next login).
    """
    # Step 1: Check Authorization header exists
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "status": "error",
                "message": "Authentication required. Please provide a Bearer token.",
                "error_code": "AUTH_TOKEN_MISSING",
            },
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials

    # Step 2: Verify JWT (signature, expiry, blacklist)
    token_service = TokenService(db)
    try:
        payload = await token_service.verify_access_token(token)
    except TokenExpiredError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "status": "error",
                "message": e.message,
                "error_code": e.error_code,
            },
            headers={"WWW-Authenticate": "Bearer"},
        )
    except (TokenInvalidError, TokenRevokedError) as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "status": "error",
                "message": e.message,
                "error_code": e.error_code,
            },
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Step 3: Extract user_id from token payload
    user_id_str = payload.get("sub")
    if not user_id_str:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "status": "error",
                "message": "Invalid token payload.",
                "error_code": "AUTH_TOKEN_INVALID",
            },
        )

    # Step 4: Load user from database
    import uuid
    try:
        user_id = uuid.UUID(user_id_str)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "status": "error",
                "message": "Invalid token payload.",
                "error_code": "AUTH_TOKEN_INVALID",
            },
        )

    user_repo = UserRepository(db)
    user = await user_repo.get_by_id(user_id)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "status": "error",
                "message": "User account not found.",
                "error_code": "AUTH_USER_NOT_FOUND",
            },
        )

    # Step 5: Verify account is still active
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "status": "error",
                "message": "Your account has been deactivated.",
                "error_code": "AUTH_ACCOUNT_DISABLED",
            },
        )

    return user


def require_roles(required_roles: list[str]):
    """
    Role-based access control dependency factory.

    Returns a dependency that checks the current user has
    at least ONE of the required roles.

    Usage:
        # Single role required
        @router.get("/admin/users")
        async def list_users(
            current_user: User = Depends(require_roles(["admin"]))
        ):
            ...

        # Either role accepted
        @router.delete("/posts/{id}")
        async def delete_post(
            current_user: User = Depends(require_roles(["admin", "moderator"]))
        ):
            ...

    WHY a factory function (returns a function)?
    require_roles(["admin"]) is called at route DEFINITION time.
    It returns a dependency function that FastAPI calls at REQUEST time.
    This lets us pass the role list as a parameter.
    """

    async def role_checker(
        current_user: User = Depends(get_current_user),
    ) -> User:
        """
        Inner dependency: verifies the authenticated user's roles.
        Wraps get_current_user — auth happens first, then role check.
        """
        user_roles = current_user.role_names

        # Check if user has ANY of the required roles (OR logic)
        has_required_role = any(
            role in user_roles for role in required_roles
        )

        if not has_required_role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "status": "error",
                    "message": "You don't have permission to access this resource.",
                    "error_code": "AUTH_INSUFFICIENT_PERMISSIONS",
                    "details": {
                        "required_roles": required_roles,
                        "your_roles": user_roles,
                    },
                },
            )

        return current_user

    return role_checker


def get_optional_user(
    credentials: Annotated[
        HTTPAuthorizationCredentials | None,
        Depends(bearer_scheme),
    ],
    db: AsyncSession = Depends(get_db),
):
    """
    Optional authentication dependency.

    Returns the current user if a valid token is provided,
    or None if no token is present.

    Useful for endpoints that behave differently for
    authenticated vs anonymous users but don't REQUIRE auth.

    Usage:
        @router.get("/posts")
        async def list_posts(
            current_user: User | None = Depends(get_optional_user)
        ):
            if current_user:
                # Show personalized content
            else:
                # Show public content
    """
    if not credentials:
        return None

    # We use a nested dependency call pattern here
    # If token is invalid, return None instead of raising
    async def _get_optional(db: AsyncSession = Depends(get_db)):
        try:
            token_service = TokenService(db)
            payload = await token_service.verify_access_token(
                credentials.credentials
            )
            import uuid
            user_id = uuid.UUID(payload.get("sub", ""))
            user_repo = UserRepository(db)
            return await user_repo.get_by_id(user_id)
        except Exception:
            return None

    return _get_optional


# ── Type Aliases ─────────────────────────────────────────────────
# These make route signatures cleaner and more readable.
# Instead of: current_user: User = Depends(get_current_user)
# You can write: current_user: CurrentUser

CurrentUser = Annotated[User, Depends(get_current_user)]
AdminUser = Annotated[User, Depends(require_roles(["admin"]))]
ModeratorUser = Annotated[User, Depends(require_roles(["admin", "moderator"]))]

# Re-export get_db for convenience
__all__ = [
    "get_db",
    "get_current_user",
    "require_roles",
    "get_optional_user",
    "CurrentUser",
    "AdminUser",
    "ModeratorUser",
]