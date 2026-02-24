"""

User profile endpoints — all require authentication.
This is our first real use of the JWT middleware.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies import CurrentUser, get_db
from app.models.user import User
from app.repositories.user_repository import UserRepository
from app.schemas.common import StandardResponse
from app.schemas.user import UpdateProfileRequest, UserResponse

router = APIRouter()


@router.get(
    "/me",
    response_model=StandardResponse[UserResponse],
    summary="Get current user profile",
)
async def get_my_profile(
    current_user: CurrentUser,   # ← JWT middleware runs automatically
):
    """
    Returns the authenticated user's profile.

    The 'CurrentUser' type alias means FastAPI will:
    1. Extract the Bearer token from Authorization header
    2. Verify the JWT
    3. Check the blacklist
    4. Load the user from DB
    5. Inject the User object as 'current_user'

    If any step fails, this handler never runs — the client
    gets a 401 automatically.
    """
    return StandardResponse.success(
        message="Profile retrieved successfully.",
        data=UserResponse.from_user(current_user),
    )


@router.patch(
    "/me",
    response_model=StandardResponse[UserResponse],
    summary="Update current user profile",
)
async def update_my_profile(
    update_data: UpdateProfileRequest,
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
):
    """
    Update the authenticated user's profile.
    Only full_name and avatar_url can be changed here.
    Email and password have their own dedicated endpoints.
    """
    # Build update dict with only the fields that were provided
    # (None means "not provided" — we skip those)
    updates = {}
    if update_data.full_name is not None:
        if len(update_data.full_name.strip()) < 2:
            from fastapi import HTTPException, status
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Full name must be at least 2 characters.",
            )
        updates["full_name"] = update_data.full_name.strip()

    if update_data.avatar_url is not None:
        updates["avatar_url"] = update_data.avatar_url

    if updates:
        user_repo = UserRepository(db)
        current_user = await user_repo.update(current_user, **updates)
        await db.commit()
        await db.refresh(current_user)

    return StandardResponse.success(
        message="Profile updated successfully.",
        data=UserResponse.from_user(current_user),
    )