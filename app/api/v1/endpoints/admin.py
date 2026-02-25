"""

Admin-only endpoints for user and session management.

Every endpoint here uses Depends(require_roles(["admin"])).
If the authenticated user doesn't have the admin role,
they get a 403 Forbidden before the handler even runs.

This is RBAC in action:
- Authentication (who are you?) → get_current_user()
- Authorization (what can you do?) → require_roles(["admin"])
"""

import uuid

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies import AdminUser, get_db
from app.schemas.admin import (
    AdminSessionResponse,
    AdminUserListResponse,
    AdminUserResponse,
    RoleUpdateRequest,
    StatusUpdateRequest,
)
from app.schemas.common import StandardResponse
from app.services.admin_service import AdminService

router = APIRouter()


@router.get(
    "/users",
    response_model=StandardResponse[AdminUserListResponse],
    summary="List all users",
    description="Paginated list of all users. Supports search and filtering.",
)
async def list_users(
    # AdminUser = Depends(require_roles(["admin"])) under the hood
    current_admin: AdminUser,
    db: AsyncSession = Depends(get_db),
    # Query parameters with defaults and validation
    page: int = Query(default=1, ge=1, description="Page number"),
    limit: int = Query(default=20, ge=1, le=100, description="Results per page"),
    search: str | None = Query(default=None, description="Search by email or name"),
    is_active: bool | None = Query(default=None, description="Filter by active status"),
    role: str | None = Query(default=None, description="Filter by role name"),
):
    """
    List all users with pagination and filtering.

    Only accessible by admin users. Returns full user details
    including account status and role assignments.
    """
    service = AdminService(db)
    result = await service.list_users(
        page=page,
        limit=limit,
        search=search,
        is_active=is_active,
        role=role,
    )

    return StandardResponse.success(
        message="Users retrieved successfully.",
        data=AdminUserListResponse(
            users=[AdminUserResponse.from_user(u) for u in result["users"]],
            total=result["total"],
            page=result["page"],
            limit=result["limit"],
            total_pages=result["total_pages"],
        ),
    )


@router.get(
    "/users/{user_id}",
    response_model=StandardResponse[AdminUserResponse],
    summary="Get specific user details",
)
async def get_user(
    user_id: uuid.UUID,
    current_admin: AdminUser,
    db: AsyncSession = Depends(get_db),
):
    """Get complete details for a specific user by their UUID."""
    service = AdminService(db)
    user = await service.get_user(user_id)

    return StandardResponse.success(
        message="User retrieved successfully.",
        data=AdminUserResponse.from_user(user),
    )


@router.patch(
    "/users/{user_id}/roles",
    response_model=StandardResponse[AdminUserResponse],
    summary="Update user roles",
    description=(
        "Replaces the user's entire role set. "
        "Send the complete list of roles you want the user to have."
    ),
)
async def update_user_roles(
    user_id: uuid.UUID,
    request_data: RoleUpdateRequest,
    current_admin: AdminUser,
    db: AsyncSession = Depends(get_db),
):
    """
    Replace a user's roles entirely.

    Example: Send {"roles": ["user", "moderator"]} to make
    the user both a regular user and a moderator.

    The admin's own role cannot be removed from their account.
    """
    # Validate the role names
    try:
        valid_roles = request_data.validate_roles()
    except ValueError as e:
        from fastapi import HTTPException
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e),
        )

    service = AdminService(db)
    user = await service.update_user_roles(
        user_id=user_id,
        role_names=valid_roles,
        admin_user_id=current_admin.id,
    )

    return StandardResponse.success(
        message="User roles updated successfully.",
        data=AdminUserResponse.from_user(user),
    )


@router.patch(
    "/users/{user_id}/status",
    response_model=StandardResponse[AdminUserResponse],
    summary="Activate or deactivate a user account",
)
async def update_user_status(
    user_id: uuid.UUID,
    request_data: StatusUpdateRequest,
    current_admin: AdminUser,
    db: AsyncSession = Depends(get_db),
):
    """
    Activate or deactivate a user account.

    Deactivating immediately revokes all sessions and tokens —
    the user is locked out of all devices instantly.
    """
    service = AdminService(db)
    user = await service.update_user_status(
        user_id=user_id,
        is_active=request_data.is_active,
        admin_user_id=current_admin.id,
    )

    action = "activated" if request_data.is_active else "deactivated"
    return StandardResponse.success(
        message=f"User account {action} successfully.",
        data=AdminUserResponse.from_user(user),
    )


@router.get(
    "/users/{user_id}/sessions",
    response_model=StandardResponse[list[AdminSessionResponse]],
    summary="Get all sessions for a user",
)
async def get_user_sessions(
    user_id: uuid.UUID,
    current_admin: AdminUser,
    db: AsyncSession = Depends(get_db),
):
    """Get all active sessions for a specific user."""
    service = AdminService(db)
    sessions = await service.get_user_sessions(user_id)

    return StandardResponse.success(
        message="Sessions retrieved successfully.",
        data=[
            AdminSessionResponse(
                id=s.id,
                user_id=s.user_id,
                ip_address=s.ip_address,
                user_agent=s.user_agent,
                device_info=s.device_info,
                is_active=s.is_active,
                last_active_at=s.last_active_at,
                created_at=s.created_at,
                expires_at=s.expires_at,
            )
            for s in sessions
        ],
    )


@router.delete(
    "/users/{user_id}/sessions",
    response_model=StandardResponse,
    summary="Revoke all sessions for a user",
)
async def revoke_user_sessions(
    user_id: uuid.UUID,
    current_admin: AdminUser,
    db: AsyncSession = Depends(get_db),
):
    """
    Force-logout a user from all devices.
    Revokes all refresh tokens and deactivates all sessions.
    """
    service = AdminService(db)
    await service.revoke_all_user_sessions(
        user_id=user_id,
        admin_user_id=current_admin.id,
    )

    return StandardResponse.success(
        message="All sessions revoked successfully. User has been logged out of all devices.",
    )