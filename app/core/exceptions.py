"""

Custom exception classes for AuthShield.

WHY CUSTOM EXCEPTIONS?
Instead of returning HTTP responses directly from service code
(which would couple business logic to HTTP), we raise typed exceptions.
The API layer catches these and converts them to appropriate HTTP responses.

This means:
- Services know nothing about HTTP status codes
- Error handling is centralized (one place to change response format)
- Exceptions are self-documenting (the name tells you what went wrong)
"""

from typing import Any


class AuthShieldException(Exception):
    """
    Base exception for all AuthShield errors.
    All custom exceptions inherit from this so you can catch
    'any AuthShield error' with a single except clause.
    """

    def __init__(
        self,
        message: str,
        error_code: str = "UNKNOWN_ERROR",
        details: Any = None,
    ):
        self.message = message
        self.error_code = error_code
        self.details = details
        super().__init__(message)


# ── Authentication Errors ────────────────────────────────────────

class InvalidCredentialsError(AuthShieldException):
    """Wrong email or password during login."""
    def __init__(self):
        super().__init__(
            message="The email or password you entered is incorrect.",
            error_code="AUTH_INVALID_CREDENTIALS",
        )


class EmailNotVerifiedError(AuthShieldException):
    """User hasn't verified their email address yet."""
    def __init__(self):
        super().__init__(
            message="Please verify your email address before logging in.",
            error_code="AUTH_EMAIL_NOT_VERIFIED",
        )


class AccountDisabledError(AuthShieldException):
    """Admin has deactivated this account."""
    def __init__(self):
        super().__init__(
            message="Your account has been deactivated. Please contact support.",
            error_code="AUTH_ACCOUNT_DISABLED",
        )


class TokenExpiredError(AuthShieldException):
    """JWT access token has expired."""
    def __init__(self):
        super().__init__(
            message="Your session has expired. Please log in again.",
            error_code="AUTH_TOKEN_EXPIRED",
        )


class TokenInvalidError(AuthShieldException):
    """JWT is malformed or signature is invalid."""
    def __init__(self):
        super().__init__(
            message="Invalid token. Please log in again.",
            error_code="AUTH_TOKEN_INVALID",
        )


class TokenRevokedError(AuthShieldException):
    """JWT has been blacklisted (user logged out)."""
    def __init__(self):
        super().__init__(
            message="Token has been revoked. Please log in again.",
            error_code="AUTH_TOKEN_REVOKED",
        )


class RefreshTokenInvalidError(AuthShieldException):
    """Refresh token not found, expired, or revoked."""
    def __init__(self):
        super().__init__(
            message="Invalid or expired refresh token. Please log in again.",
            error_code="AUTH_REFRESH_TOKEN_INVALID",
        )


class RefreshTokenReuseError(AuthShieldException):
    """
    A refresh token that was already used was presented again.
    This indicates token theft. All sessions for this user are revoked.
    """
    def __init__(self):
        super().__init__(
            message=(
                "Security alert: token reuse detected. "
                "All sessions have been revoked for your protection. "
                "Please log in again."
            ),
            error_code="AUTH_REFRESH_TOKEN_REUSED",
        )


class InsufficientPermissionsError(AuthShieldException):
    """User doesn't have the required role for this endpoint."""
    def __init__(self, required_roles: list[str] | None = None):
        detail = f"Required roles: {required_roles}" if required_roles else None
        super().__init__(
            message="You don't have permission to access this resource.",
            error_code="AUTH_INSUFFICIENT_PERMISSIONS",
            details=detail,
        )


class TwoFactorRequiredError(AuthShieldException):
    """
    Raised during login when 2FA is enabled.
    Carries a temp_token the client uses to complete 2FA verification.
    The temp_token is stored in Redis for 5 minutes.
    """
    def __init__(self, temp_token: str = ""):
        super().__init__(
            message="Two-factor authentication required.",
            error_code="AUTH_2FA_REQUIRED",
        )
        self.temp_token = temp_token


class TwoFactorNotEnabledError(AuthShieldException):
    def __init__(self):
        super().__init__(
            message="Two-factor authentication is not enabled on this account.",
            error_code="AUTH_2FA_NOT_ENABLED",
        )

class TwoFactorAlreadyEnabledError(AuthShieldException):
    def __init__(self):
        super().__init__(
            message="Two-factor authentication is already enabled on this account.",
            error_code="AUTH_2FA_ALREADY_ENABLED",
        )


class TwoFactorInvalidError(AuthShieldException):
    def __init__(self, message: str = "Invalid or expired 2FA code."):
        super().__init__(
            message=message,
            error_code="AUTH_2FA_INVALID",
        )


# ── User / Registration Errors ───────────────────────────────────

class EmailAlreadyRegisteredError(AuthShieldException):
    """Attempted to register with an email that already exists."""
    def __init__(self):
        super().__init__(
            message="An account with this email address already exists.",
            error_code="AUTH_EMAIL_ALREADY_REGISTERED",
        )


class UserNotFoundError(AuthShieldException):
    """Requested user does not exist."""
    def __init__(self):
        super().__init__(
            message="User not found.",
            error_code="USER_NOT_FOUND",
        )


class InvalidVerificationTokenError(AuthShieldException):
    """Email verification token is invalid or expired."""
    def __init__(self):
        super().__init__(
            message="This verification link is invalid or has expired. Please request a new one.",
            error_code="AUTH_INVALID_VERIFICATION_TOKEN",
        )


class InvalidResetTokenError(AuthShieldException):
    """Password reset token is invalid or expired."""
    def __init__(self):
        super().__init__(
            message="This reset link is invalid or has expired. Please request a new one.",
            error_code="AUTH_INVALID_RESET_TOKEN",
        )


class PasswordMismatchError(AuthShieldException):
    """Current password provided during change-password is wrong."""
    def __init__(self):
        super().__init__(
            message="Current password is incorrect.",
            error_code="AUTH_PASSWORD_MISMATCH",
        )


class SamePasswordError(AuthShieldException):
    """New password is identical to the current password."""
    def __init__(self):
        super().__init__(
            message="New password must be different from your current password.",
            error_code="AUTH_SAME_PASSWORD",
        )


# ── Session Errors ────────────────────────────────────────────────

class SessionNotFoundError(AuthShieldException):
    """Requested session doesn't exist."""
    def __init__(self):
        super().__init__(
            message="Session not found.",
            error_code="SESSION_NOT_FOUND",
        )


class SessionOwnershipError(AuthShieldException):
    """User tried to revoke a session belonging to another user."""
    def __init__(self):
        super().__init__(
            message="You don't have permission to revoke this session.",
            error_code="SESSION_OWNERSHIP_ERROR",
        )


# ── Rate Limiting Errors ──────────────────────────────────────────

class RateLimitExceededError(AuthShieldException):
    """Too many requests from this IP or user."""
    def __init__(self, retry_after: int = 60):
        super().__init__(
            message=f"Too many requests. Please try again in {retry_after} seconds.",
            error_code="RATE_LIMIT_EXCEEDED",
            details={"retry_after": retry_after},
        )