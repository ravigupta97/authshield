"""

OAuth endpoints for Google (and GitHub in Step 14).

These endpoints are unusual compared to our other endpoints:

GET /oauth/google
    → Does NOT return JSON. Returns a 302 redirect.
    → The browser follows the redirect to Google's consent screen.

GET /oauth/google/callback
    → Google redirects the user's browser here after consent.
    → Receives code + state as query parameters.
    → Returns JSON with tokens (or redirects to frontend with tokens).
"""

from fastapi import APIRouter, Depends, Query, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies import get_db
from app.config import settings
from app.core.exceptions import AuthShieldException
from app.schemas.common import StandardResponse
from app.schemas.oauth import OAuthLoginResponse, OAuthUserResponse
from app.services.oauth_service import OAuthService

router = APIRouter()


@router.get(
    "/google",
    summary="Initiate Google OAuth flow",
    description=(
        "Redirects the user to Google's consent screen. "
        "After the user grants permission, Google redirects back "
        "to the callback endpoint."
    ),
)
async def google_oauth_init(
    db: AsyncSession = Depends(get_db),
):
    """
    Start the Google OAuth flow.

    The frontend triggers this by navigating the browser to this URL
    (not an API call — a full browser navigation).

    Returns a 307 redirect to Google's authorization URL.
    The browser follows this redirect automatically.
    """
    service = OAuthService(db)
    auth_url = await service.get_google_auth_url()

    return RedirectResponse(
        url=auth_url,
        status_code=status.HTTP_307_TEMPORARY_REDIRECT,
    )


@router.get(
    "/google/callback",
    response_model=StandardResponse[OAuthLoginResponse],
    summary="Google OAuth callback",
    description=(
        "Handles the callback from Google after user grants permission. "
        "Exchanges the authorization code for tokens and returns JWT credentials."
    ),
)
async def google_oauth_callback(
    request: Request,
    db: AsyncSession = Depends(get_db),
    code: str = Query(..., description="Authorization code from Google"),
    state: str = Query(..., description="CSRF state token"),
    error: str | None = Query(
        default=None,
        description="Error from Google if user denied access",
    ),
):
    """
    Google OAuth callback endpoint.

    Google redirects the user's browser here after they approve
    (or deny) access on Google's consent screen.

    Query parameters are set by Google:
    - code: authorization code (exchange this for an access token)
    - state: CSRF token (we verify this matches what we generated)
    - error: set if user denied access (e.g., "access_denied")
    """
    # Handle user denying access on Google's screen
    if error:
        return StandardResponse.error(
            message=(
                "Google sign-in was cancelled or access was denied. "
                "Please try again."
            ),
        )

    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    service = OAuthService(db)
    oauth_data = await service.handle_google_callback(
        code=code,
        state=state,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    return StandardResponse.success(
        message=(
            "Successfully signed in with Google."
            if not oauth_data["user"]["is_new_user"]
            else "Account created and signed in with Google."
        ),
        data=OAuthLoginResponse(
            access_token=oauth_data["access_token"],
            refresh_token=oauth_data["refresh_token"],
            token_type=oauth_data["token_type"],
            expires_in=oauth_data["expires_in"],
            user=OAuthUserResponse(**oauth_data["user"]),
        ),
    )


@router.get(
    "/github",
    summary="Initiate GitHub OAuth flow",
    description="Redirects the user to GitHub's authorization screen.",
)
async def github_oauth_init(
    db: AsyncSession = Depends(get_db),
):
    """Start the GitHub OAuth flow.
    The frontend triggers this by navigating the browser to this URL
    (not an API call — a full browser navigation).

    Returns a 307 redirect to GitHub's authorization URL.
    The browser follows this redirect automatically.
    """
    service = OAuthService(db)
    auth_url = await service.get_github_auth_url()

    return RedirectResponse(
        url=auth_url,
        status_code=status.HTTP_307_TEMPORARY_REDIRECT,
    )


@router.get(
    "/github/callback",
    response_model=StandardResponse[OAuthLoginResponse],
    summary="GitHub OAuth callback",
    description=(
        "Handles the callback from GitHub after user grants permission. "
        "Exchanges the authorization code for tokens and returns JWT credentials."
    ),
)
async def github_oauth_callback(
    request: Request,
    db: AsyncSession = Depends(get_db),
    code: str = Query(..., description="Authorization code from GitHub"),
    state: str = Query(..., description="CSRF state token"),
    error: str | None = Query(
        default=None,
        description="Error from GitHub if user denied access",
    ),
):
    """Handle GitHub's callback after user authorizes the app."""
    if error:
        return StandardResponse.error(
            message=(
                "GitHub sign-in was cancelled or access was denied."
                "Please try again."
            ),
        )

    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    service = OAuthService(db)
    oauth_data = await service.handle_github_callback(
        code=code,
        state=state,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    return StandardResponse.success(
        message=(
            "Successfully signed in with GitHub."
            if not oauth_data["user"]["is_new_user"]
            else "Account created and signed in with GitHub."
        ),
        data=OAuthLoginResponse(
            access_token=oauth_data["access_token"],
            refresh_token=oauth_data["refresh_token"],
            token_type=oauth_data["token_type"],
            expires_in=oauth_data["expires_in"],
            user=OAuthUserResponse(**oauth_data["user"]),
        ),
    )