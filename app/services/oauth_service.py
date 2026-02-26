"""

Business logic for OAuth authentication flows.
Currently supports Google. GitHub follows the same pattern.

DESIGN DECISIONS:

1. We use httpx (async HTTP client) directly instead of authlib's
   higher-level OAuth client. This gives us more control and
   makes the flow explicit and easy to understand.

2. Account linking: if a user registered with email/password and
   later tries Google OAuth with the same email, we link the Google
   account to their existing user — no duplicate accounts.

3. Email trust: Google verifies email addresses. If Google says the
   email is verified, we trust it and mark our user as verified too.
   No need to send a verification email for OAuth users.

4. OAuth users don't have passwords. Their password_hash is NULL.
   They can always set a password later via change-password if they
   want to also support email/password login.
"""

import uuid

import httpx
import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.exceptions import AuthShieldException
from app.core.security import generate_oauth_state
from app.db.redis import get_redis
from app.repositories.user_repository import UserRepository
from app.services.token_service import TokenService

log = structlog.get_logger()

# Redis key for OAuth state tokens (CSRF protection)
OAUTH_STATE_KEY = "oauth_state:{state}"
OAUTH_STATE_TTL = 600  # 10 minutes — user has this long to complete OAuth


class OAuthService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.user_repo = UserRepository(db)
        self.token_service = TokenService(db)

    # ── Google OAuth ──────────────────────────────────────────────

    async def get_google_auth_url(self) -> str:
        """
        Generate the Google OAuth authorization URL.

        The user's browser is redirected to this URL. Google shows
        their consent screen, the user approves, and Google redirects
        back to our callback URL with an authorization code.

        PARAMETERS:
        - client_id: identifies our application to Google
        - redirect_uri: where Google sends the user after consent
        - response_type=code: we want an authorization code (not token)
        - scope: what data we're requesting access to
        - state: CSRF protection token (we verify this in callback)
        - access_type=offline: we want a refresh token from Google
          (not strictly needed since we issue our own tokens, but
          good practice)
        - prompt=select_account: always show account picker, even if
          user is already logged into one Google account
        """
        # Generate and store state token for CSRF protection
        state = generate_oauth_state()
        redis = get_redis()
        await redis.setex(
            OAUTH_STATE_KEY.format(state=state),
            OAUTH_STATE_TTL,
            "1",  # Value doesn't matter, just existence
        )

        # Build Google's authorization URL with all required parameters
        params = {
            "client_id": settings.google_client_id,
            "redirect_uri": settings.google_redirect_uri,
            "response_type": "code",
            "scope": "openid email profile",
            "state": state,
            "access_type": "offline",
            "prompt": "select_account",
        }

        base_url = "https://accounts.google.com/o/oauth2/v2/auth"
        query_string = "&".join(f"{k}={v}" for k, v in params.items())
        return f"{base_url}?{query_string}"

    async def handle_google_callback(
        self,
        code: str,
        state: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> dict:
        """
        Handle Google's callback after user grants consent.

        Steps:
        1. Verify the state token (CSRF check)
        2. Exchange the authorization code for a Google access token
        3. Use the access token to get user info from Google
        4. Find existing user or create new one
        5. Issue our own JWT tokens
        6. Return token data

        WHY exchange code for token server-side?
        The authorization code flow keeps tokens off the browser URL.
        The code is short-lived and useless without our client secret.
        This is much safer than the implicit flow (which puts tokens
        in the URL fragment — visible in browser history, logs, etc.)
        """
        # Step 1: Verify state token (CSRF protection)
        await self._verify_oauth_state(state)

        # Step 2: Exchange authorization code for Google access token
        google_tokens = await self._exchange_code_for_tokens(
            code=code,
            provider="google",
            token_url="https://oauth2.googleapis.com/token",
            client_id=settings.google_client_id,
            client_secret=settings.google_client_secret,
            redirect_uri=settings.google_redirect_uri,
        )

        # Step 3: Get user info from Google
        user_info = await self._get_google_user_info(
            access_token=google_tokens["access_token"]
        )

        # Step 4: Find or create user in our database
        user, is_new_user = await self._find_or_create_oauth_user(
            email=user_info["email"],
            full_name=user_info.get("name", ""),
            avatar_url=user_info.get("picture"),
            provider="google",
            provider_id=user_info["id"],
            email_verified=user_info.get("verified_email", False),
        )

        # Step 5: Issue our JWT tokens
        device_info = self._parse_device_info(user_agent)
        token_data = await self.token_service.create_tokens_for_user(
            user=user,
            ip_address=ip_address,
            user_agent=user_agent,
            device_info=device_info,
        )

        await self.db.commit()

        log.info(
            "Google OAuth login successful",
            user_id=str(user.id),
            email=user.email,
            is_new_user=is_new_user,
        )

        return {
            "access_token": token_data["access_token"],
            "refresh_token": token_data["refresh_token"],
            "token_type": token_data["token_type"],
            "expires_in": token_data["expires_in"],
            "user": {
                "id": user.id,
                "email": user.email,
                "full_name": user.full_name,
                "roles": user.role_names,
                "is_2fa_enabled": user.is_2fa_enabled,
                "is_new_user": is_new_user,
            },
        }

    async def _get_google_user_info(self, access_token: str) -> dict:
        """
        Fetch the authenticated user's profile from Google.

        Google's userinfo endpoint returns the user's email,
        name, profile picture, and whether their email is verified.
        """
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://www.googleapis.com/oauth2/v2/userinfo",
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=10.0,
            )

            if response.status_code != 200:
                raise AuthShieldException(
                    message="Failed to retrieve user information from Google.",
                    error_code="OAUTH_GOOGLE_USERINFO_FAILED",
                )

            return response.json()

    # ── Shared OAuth Helpers ──────────────────────────────────────

    async def _verify_oauth_state(self, state: str) -> None:
        """
        Verify the OAuth state token to prevent CSRF attacks.

        Checks that:
        1. State token exists in Redis (we generated it)
        2. Deletes it immediately (single-use)

        NOTE: Using GET + DEL separately instead of GETDEL because
        GETDEL requires Redis 6.2+. This two-step approach works on
        all Redis versions. There is no meaningful race condition risk
        here because state tokens are single-use per browser session.
        """
        redis = get_redis()
        key = OAUTH_STATE_KEY.format(state=state)

        # Step 1: Check the token exists
        value = await redis.get(key)

        if not value:
            raise AuthShieldException(
            message=(
                "Invalid or expired OAuth state. "
                "Please try signing in again."
            ),
            error_code="OAUTH_INVALID_STATE",
        )

        # Step 2: Delete it immediately (single-use)
        await redis.delete(key)


    async def _exchange_code_for_tokens(
        self,
        code: str,
        provider: str,
        token_url: str,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
    ) -> dict:
        """
        Exchange an authorization code for OAuth tokens.

        This is the core of the Authorization Code flow.
        We POST the code + our credentials to the provider's token
        endpoint and receive an access token in return.

        The code is short-lived (usually 60 seconds) and single-use.
        The client secret never leaves our server — this is why
        the Authorization Code flow is more secure than Implicit.
        """
        async with httpx.AsyncClient() as client:
            response = await client.post(
                token_url,
                data={
                    "code": code,
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "redirect_uri": redirect_uri,
                    "grant_type": "authorization_code",
                },
                # GitHub requires Accept: application/json
                # to return JSON instead of URL-encoded form data
                headers={"Accept": "application/json"},
                timeout=10.0,
            )

            if response.status_code != 200:
                log.error(
                    f"{provider} token exchange failed",
                    status=response.status_code,
                    body=response.text,
                )
                raise AuthShieldException(
                    message=f"Failed to authenticate with {provider.title()}.",
                    error_code=f"OAUTH_{provider.upper()}_TOKEN_FAILED",
                )

            return response.json()

    async def _find_or_create_oauth_user(
        self,
        email: str,
        full_name: str,
        avatar_url: str | None,
        provider: str,
        provider_id: str,
        email_verified: bool,
    ) -> tuple:
        """
        Find an existing user or create a new one for OAuth login.

        ACCOUNT LINKING LOGIC:
        Case 1: User exists with this provider+provider_id
                → Returning OAuth user. Update their info. Return user.

        Case 2: User exists with this email (registered via password)
                → Link OAuth to existing account. Now supports both
                  login methods. Return existing user.

        Case 3: No user found
                → New user. Create account. Assign default role.
                  Mark as verified (OAuth provider already verified email).

        WHY update avatar on every login?
        Users change their Google profile picture. We keep it fresh.
        Email and name are NOT updated — they might have customized
        them in our system.
        """
        is_new_user = False

        # Case 1: Find by OAuth provider + provider ID
        user = await self.user_repo.get_by_oauth(
            provider=provider,
            oauth_id=provider_id,
        )

        if user:
            # Returning OAuth user — update avatar in case it changed
            if avatar_url and user.avatar_url != avatar_url:
                await self.user_repo.update(user, avatar_url=avatar_url)
            return user, is_new_user

        # Case 2: Find by email (existing email/password user)
        user = await self.user_repo.get_by_email(email)

        if user:
            # Link OAuth to their existing account
            await self.user_repo.update(
                user,
                oauth_provider=provider,
                oauth_id=provider_id,
                avatar_url=avatar_url or user.avatar_url,
                # Mark as verified since OAuth provider verified the email
                is_verified=True,
            )
            log.info(
                "OAuth linked to existing account",
                email=email,
                provider=provider,
            )
            return user, is_new_user

        # Case 3: Brand new user via OAuth
        is_new_user = True
        user = await self.user_repo.create(
            email=email,
            full_name=full_name or email.split("@")[0],
            password_hash=None,         # OAuth users have no password
            oauth_provider=provider,
            oauth_id=provider_id,
            avatar_url=avatar_url,
            is_verified=email_verified,  # Trust OAuth provider's verification
        )

        # Assign default 'user' role
        await self.user_repo.assign_role(user, "user")
        await self.db.flush()

        log.info(
            "New user created via OAuth",
            email=email,
            provider=provider,
        )

        return user, is_new_user

    def _parse_device_info(self, user_agent: str | None) -> str | None:
        """Parse human-readable device info from User-Agent string."""
        if not user_agent:
            return None

        ua = user_agent.lower()

        if "windows" in ua:
            os = "Windows"
        elif "macintosh" in ua or "mac os" in ua:
            os = "macOS"
        elif "iphone" in ua:
            os = "iPhone"
        elif "android" in ua:
            os = "Android"
        elif "linux" in ua:
            os = "Linux"
        else:
            os = "Unknown OS"

        if "edg/" in ua:
            browser = "Edge"
        elif "chrome" in ua and "chromium" not in ua:
            browser = "Chrome"
        elif "firefox" in ua:
            browser = "Firefox"
        elif "safari" in ua and "chrome" not in ua:
            browser = "Safari"
        else:
            browser = "Unknown Browser"

        return f"{browser} on {os}"
    
    # ── GitHub OAuth ──────────────────────────────────────────────

    async def get_github_auth_url(self) -> str:
        """
        Generate the GitHub OAuth authorization URL.

        GitHub's OAuth flow is nearly identical to Google's.
        Key differences:
        - Different authorization URL
        - scope is 'user:email' (not openid email profile)
        - GitHub doesn't always return email in the main profile
        endpoint — we need a separate /user/emails call
        - No access_type or prompt parameters
        """
        state = generate_oauth_state()
        redis = get_redis()
        await redis.setex(
            OAUTH_STATE_KEY.format(state=state),
            OAUTH_STATE_TTL,
            "1",
        )

        params = {
            "client_id": settings.github_client_id,
            "redirect_uri": settings.github_redirect_uri,
            "scope": "user:email",
            "state": state,
        }

        base_url = "https://github.com/login/oauth/authorize"
        query_string = "&".join(f"{k}={v}" for k, v in params.items())
        return f"{base_url}?{query_string}"

    async def handle_github_callback(
        self,
        code: str,
        state: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> dict:
        """
        Handle GitHub's callback after user grants consent.

        Same pattern as Google but with GitHub-specific endpoints.
        GitHub's user info is split across two endpoints:
        - GET /user: profile data (name, avatar, id)
        - GET /user/emails: email addresses (needed if email is private)
        """
        # Step 1: Verify CSRF state
        await self._verify_oauth_state(state)

        # Step 2: Exchange code for GitHub access token
        github_tokens = await self._exchange_code_for_tokens(
            code=code,
            provider="github",
            token_url="https://github.com/login/oauth/access_token",
            client_id=settings.github_client_id,
            client_secret=settings.github_client_secret,
            redirect_uri=settings.github_redirect_uri,
        )

        access_token = github_tokens.get("access_token")
        if not access_token:
            raise AuthShieldException(
                message="Failed to obtain access token from GitHub.",
                error_code="OAUTH_GITHUB_TOKEN_FAILED",
            )

        # Step 3: Get user profile from GitHub
        user_info = await self._get_github_user_info(access_token)

        # Step 4: Find or create user
        user, is_new_user = await self._find_or_create_oauth_user(
            email=user_info["email"],
            full_name=user_info.get("name") or user_info.get("login", ""),
            avatar_url=user_info.get("avatar_url"),
            provider="github",
            provider_id=str(user_info["id"]),
            email_verified=True,   # GitHub verifies emails before showing them
        )

        # Step 5: Issue JWT tokens
        device_info = self._parse_device_info(user_agent)
        token_data = await self.token_service.create_tokens_for_user(
            user=user,
            ip_address=ip_address,
            user_agent=user_agent,
            device_info=device_info,
        )

        await self.db.commit()

        log.info(
            "GitHub OAuth login successful",
            user_id=str(user.id),
            email=user_info["email"],
            is_new_user=is_new_user,
        )

        return {
            "access_token": token_data["access_token"],
            "refresh_token": token_data["refresh_token"],
            "token_type": token_data["token_type"],
            "expires_in": token_data["expires_in"],
            "user": {
                "id": user.id,
                "email": user_info["email"],
                "full_name": user.full_name,
                "roles": user.role_names,
                "is_2fa_enabled": user.is_2fa_enabled,
                "is_new_user": is_new_user,
            },
        }

    async def _get_github_user_info(self, access_token: str) -> dict:
        """
        Fetch user profile and email from GitHub.

        GitHub requires two separate API calls:
        1. GET /user        → profile (id, name, avatar, login)
        2. GET /user/emails → email list (needed for private emails)

        WHY two calls for email?
        GitHub users can set their email to private. In that case,
        the /user endpoint returns null for email. We must call
        /user/emails to get the verified primary email address.
        """
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        async with httpx.AsyncClient() as client:
            # Get profile
            profile_response = await client.get(
                "https://api.github.com/user",
                headers=headers,
                timeout=10.0,
            )
            if profile_response.status_code != 200:
                raise AuthShieldException(
                    message="Failed to retrieve profile from GitHub.",
                    error_code="OAUTH_GITHUB_PROFILE_FAILED",
                )
            profile = profile_response.json()

            # Get emails (handles private email setting)
            emails_response = await client.get(
                "https://api.github.com/user/emails",
                headers=headers,
                timeout=10.0,
            )
            if emails_response.status_code != 200:
                raise AuthShieldException(
                    message="Failed to retrieve email from GitHub.",
                    error_code="OAUTH_GITHUB_EMAIL_FAILED",
                )
            emails = emails_response.json()

        # Find the primary verified email
        # GitHub can have multiple emails — we want primary + verified
        primary_email = None
        for email_obj in emails:
            if email_obj.get("primary") and email_obj.get("verified"):
                primary_email = email_obj["email"]
                break

        # Fallback: any verified email
        if not primary_email:
            for email_obj in emails:
                if email_obj.get("verified"):
                    primary_email = email_obj["email"]
                    break

        if not primary_email:
            raise AuthShieldException(
                message=(
                    "No verified email found on your GitHub account. "
                    "Please add and verify an email on GitHub, then try again."
                ),
                error_code="OAUTH_GITHUB_NO_EMAIL",
            )

        profile["email"] = primary_email
        return profile