"""

Cryptographic utilities: password hashing, JWT operations,
and secure token generation.

Everything in this file is STATELESS — pure functions with no
side effects. They take inputs and return outputs. Easy to test,
easy to reason about.
"""

import secrets
import string
from datetime import datetime, timedelta, timezone

import jwt
from passlib.context import CryptContext

from app.config import settings

# ── Password Hashing ─────────────────────────────────────────────

# CryptContext manages multiple hashing schemes.
# 'bcrypt' is our scheme. 'deprecated="auto"' means if we ever add
# a new scheme, old hashes are automatically flagged for rehashing.
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=settings.bcrypt_rounds,  # Work factor (12 = ~250ms per hash)
)


def hash_password(plain_password: str) -> str:
    """
    Hash a plain-text password using bcrypt.

    bcrypt automatically:
    - Generates a random salt (different hash every time, even same password)
    - Embeds the salt in the hash output
    - Applies the work factor (rounds) to slow down brute force

    The output looks like:
    $2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/HS.iK8.
    $2b$ = bcrypt identifier
    12   = work factor
    rest = salt + hash combined
    """
    return pwd_context.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain-text password against a stored bcrypt hash.

    passlib handles extracting the salt from the hash and
    re-hashing the plain password for comparison.
    Returns True if they match, False otherwise.
    NEVER raises an exception on mismatch — just returns False.
    """
    return pwd_context.verify(plain_password, hashed_password)


def validate_password_strength(password: str) -> list[str]:
    """
    Validate password meets our security requirements.
    Returns a list of error messages. Empty list = password is valid.

    WHY RETURN ERRORS INSTEAD OF RAISING?
    We want to return ALL errors at once so the user can fix
    everything in one go, not play whack-a-mole one error at a time.
    """
    errors = []

    if len(password) < settings.password_min_length:
        errors.append(
            f"Password must be at least {settings.password_min_length} characters long."
        )

    if len(password) > settings.password_max_length:
        errors.append(
            f"Password must not exceed {settings.password_max_length} characters."
        )

    if not any(c.isupper() for c in password):
        errors.append("Password must contain at least one uppercase letter (A-Z).")

    if not any(c.islower() for c in password):
        errors.append("Password must contain at least one lowercase letter (a-z).")

    if not any(c.isdigit() for c in password):
        errors.append("Password must contain at least one digit (0-9).")

    special_chars = set("!@#$%^&*()_+-=[]{}|;':\",./<>?")
    if not any(c in special_chars for c in password):
        errors.append(
            "Password must contain at least one special character (!@#$%^&* etc)."
        )

    return errors


# ── Secure Token Generation ───────────────────────────────────────

def generate_secure_token(length: int = 64) -> str:
    """
    Generate a cryptographically secure random token.

    Used for: email verification tokens, password reset tokens.
    NOT used for JWT (that's handled separately below).

    secrets.token_urlsafe() uses os.urandom() under the hood —
    the OS's cryptographic random number generator.
    This is safe for security-sensitive tokens.

    length=64 → produces ~86 character URL-safe base64 string.
    """
    return secrets.token_urlsafe(length)


# ── JWT Operations ────────────────────────────────────────────────

def create_access_token(
    user_id: str,
    email: str,
    roles: list[str],
    session_id: str,
) -> tuple[str, str]:
    """
    Create a signed JWT access token.

    Returns a tuple of (encoded_token, jti) where:
    - encoded_token: the JWT string to send to the client
    - jti: the unique token ID (used for blacklisting on logout)

    PAYLOAD CLAIMS:
    - sub: Subject. Standard JWT claim. Who this token is about.
    - email: Included so consuming services don't need DB lookup.
    - roles: Included for RBAC checks without DB lookup.
    - session_id: Links token to its session for revocation.
    - jti: JWT ID. Unique per token. Used as Redis blacklist key.
    - type: Distinguishes access tokens from other token types.
    - iat: Issued At. Standard JWT claim.
    - exp: Expiration. Standard JWT claim. PyJWT enforces this.
    """
    now = datetime.now(timezone.utc)
    jti = generate_secure_token(32)  # Unique token ID

    payload = {
        "sub": str(user_id),
        "email": email,
        "roles": roles,
        "session_id": str(session_id),
        "jti": jti,
        "type": "access",
        "iat": now,
        "exp": now + timedelta(minutes=settings.access_token_expire_minutes),
    }

    encoded = jwt.encode(
        payload,
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )

    return encoded, jti


def decode_access_token(token: str) -> dict:
    """
    Decode and verify a JWT access token.

    PyJWT automatically verifies:
    - Signature (was it signed with our secret?)
    - Expiration (is exp in the future?)
    - Algorithm (is it the algorithm we expect?)

    Raises:
    - jwt.ExpiredSignatureError: Token has expired
    - jwt.InvalidTokenError: Token is malformed or signature invalid
    """
    return jwt.decode(
        token,
        settings.jwt_secret_key,
        algorithms=[settings.jwt_algorithm],
    )


def create_refresh_token() -> str:
    """
    Generate a cryptographically secure refresh token.

    WHY NOT JWT for refresh tokens?
    Refresh tokens are ALWAYS verified against the database anyway
    (to check is_used, is_revoked, family_id). JWT's self-contained
    nature adds zero benefit here. A random string is simpler,
    smaller, and equally secure.

    The 'rt_' prefix makes it easy to identify in logs.
    """
    return f"rt_{generate_secure_token(64)}"


def generate_oauth_state() -> str:
    """
    Generate a cryptographically secure state parameter for OAuth.

    The state parameter is a CSRF protection mechanism.

    HOW IT WORKS:
    1. We generate a random state token before redirecting to Google
    2. We store it in Redis with a short TTL
    3. Google includes it in the callback URL
    4. We verify the callback's state matches what we stored
    5. If it doesn't match → CSRF attack → reject the request

    WHY is this necessary?
    Without state, an attacker could craft a malicious callback URL
    and trick a user's browser into completing an OAuth flow the
    attacker initiated — linking the attacker's Google account to
    the victim's session.
    """
    return generate_secure_token(32)