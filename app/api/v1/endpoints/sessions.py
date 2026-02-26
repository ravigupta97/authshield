"""

Session management endpoints for authenticated users.

Users can:
- View all their active sessions (GET /sessions)
- Revoke a specific session (DELETE /sessions/{id})

The current session is identified via the session_id embedded
in the JWT payload. This lets the frontend mark "This device"
and handle the current session specially (warn before revoking).
"""

import uuid

from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies import CurrentUser, get_db
from app.schemas.common import StandardResponse
from app.schemas.session import SessionListResponse, SessionResponse
from app.services.session_service import SessionService

router = APIRouter()


def _get_session_id_from_request(request: Request) -> uuid.UUID | None:
    """
    Extract the current session_id from the JWT payload stored
    on request.state by get_current_user().

    Returns None if not available (shouldn't happen for authenticated
    requests, but we handle it gracefully).
    """
    payload = getattr(request.state, "token_payload", {})
    session_id_str = payload.get("session_id")
    if not session_id_str:
        return None
    try:
        return uuid.UUID(session_id_str)
    except (ValueError, AttributeError):
        return None


def _get_jti_from_request(request: Request) -> str | None:
    """Extract JTI from the JWT payload stored on request.state."""
    payload = getattr(request.state, "token_payload", {})
    return payload.get("jti")


def _get_exp_from_request(request: Request) -> int | None:
    """Extract expiry timestamp from the JWT payload on request.state."""
    payload = getattr(request.state, "token_payload", {})
    return payload.get("exp")


@router.get(
    "",
    response_model=StandardResponse[SessionListResponse],
    summary="List all active sessions",
    description=(
        "Returns all active sessions for the current user. "
        "The current session is marked with is_current=true."
    ),
)
async def list_sessions(
    request: Request,
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
):
    """
    List all active sessions for the authenticated user.
    """
    current_session_id = _get_session_id_from_request(request)

    service = SessionService(db)
    sessions_data = await service.list_user_sessions(
        user_id=current_user.id,
        current_session_id=current_session_id,
    )

    return StandardResponse.success(
        message="Sessions retrieved successfully.",
        data=SessionListResponse(
            sessions=[SessionResponse(**s) for s in sessions_data],
            total=len(sessions_data),
        ),
    )


@router.delete(
    "/{session_id}",
    response_model=StandardResponse,
    summary="Revoke a specific session",
)
async def revoke_session(
    session_id: uuid.UUID,
    request: Request,
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
):
    """
    Revoke a specific session by its ID.
    Only your own sessions can be revoked.
    """
    # Pass current token info so we can blacklist it
    # if the user is revoking their own current session
    current_jti = _get_jti_from_request(request)
    current_exp = _get_exp_from_request(request)
    current_session_id = _get_session_id_from_request(request)

    service = SessionService(db)
    await service.revoke_session(
        session_id=session_id,
        user_id=current_user.id,
        current_session_id=current_session_id,
        current_access_token_jti=current_jti,
        current_access_token_exp=current_exp,
    )

    # Determine the right message based on whether current session was revoked
    is_current = current_session_id == session_id
    message = (
        "Logged out successfully."
        if is_current
        else "Session revoked successfully. That device has been logged out."
    )

    return StandardResponse.success(message=message)
