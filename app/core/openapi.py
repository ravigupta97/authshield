"""

Custom OpenAPI schema with full documentation and testing guide.
"""

from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi


def custom_openapi(app: FastAPI):
    """Generate and cache a custom OpenAPI schema."""
    if app.openapi_schema:
        return app.openapi_schema

    schema = get_openapi(
        title="AuthShield API",
        version="1.0.0",
        summary="A standalone authentication and authorization microservice.",
        description="""
## 🔐AuthShield

A production-ready authentication and authorization microservice with a dedicated API, built for seamless integration with any frontend or backend system.

### 📊Features:

- **Email/Password Authentication** with bcrypt hashing
- **JWT Tokens** — short-lived access tokens (15 min) + rotating refresh tokens (7 days)
- **OAuth 2.0** — Google and GitHub social login with account linking
- **Two-Factor Authentication** — TOTP (Google Authenticator / Authy)
- **Role-Based Access Control** — user, moderator, admin roles
- **Session Management** — view and revoke sessions across devices
- **Rate Limiting** — Redis sliding window protection on sensitive endpoints
- **Password Management** — secure reset flow via email

---

## 📋How to Test This API

### Step 1️⃣ — Register an Account
```
POST /auth/register
{
  "email": "you@example.com",
  "password": "YourPass123!",
  "full_name": "Your Name"
}
```
Check your email inbox for a verification link.

---

### Step 2️⃣ — Verify Your Email
Copy the token from the email link and call:
```
POST /auth/verify-email
{
  "token": "paste-token-here"
}
```

---

### Step 3️⃣ — Login
```
POST /auth/login
{
  "email": "you@example.com",
  "password": "YourPass123!"
}
```
Response contains `access_token` and `refresh_token`. Save both.

---

### Step 4️⃣ — Authorize in Swagger UI
1. Click the **Authorize** button (🔒) at the top right of this page
2. Paste your `access_token` into the **BearerAuth** field
3. Click **Authorize** → **Close**

All protected endpoints will now include your token automatically.

---

### Step 5️⃣ — Access Protected Endpoints
```
GET /users/me          → Your profile
GET /sessions          → Your active sessions
PATCH /users/me        → Update your profile
POST /auth/logout      → Logout current session
POST /auth/logout-all  → Logout all devices
```

---

### Step 6️⃣ — Refresh Your Token
When the access token expires (after 15 min):
```
POST /auth/refresh
{
  "refresh_token": "your-refresh-token"
}
```
Returns a **new** access and refresh token pair. Store both — the old refresh token is immediately invalidated.

---

### Step 7️⃣ — Try Social Login
Navigate your browser to:
- Google: `GET /auth/oauth/google`
- GitHub: `GET /auth/oauth/github`

These redirect to the provider's consent screen and return JWT tokens on completion.

---

### Step 8️⃣ — Enable Two-Factor Authentication
```
POST /auth/2fa/enable         → Get QR code
```
Scan the QR code with Google Authenticator or Authy, then:
```
POST /auth/2fa/confirm
{
  "totp_code": "123456"
}
```
On next login, you'll receive `AUTH_2FA_REQUIRED` with a `temp_token`. Complete login with:
```
POST /auth/2fa/verify
{
  "temp_token": "from-login-response",
  "totp_code": "123456"
}
```

---

### 🖋️Admin Endpoints
To access admin endpoints, your account needs the `admin` role.
Assign it directly in the database:
```sql
INSERT INTO user_roles (user_id, role_id)
SELECT 'your-user-uuid', id FROM roles WHERE name = 'admin'
ON CONFLICT DO NOTHING;
```
Then login again to get a fresh token with the admin role embedded.

---

## 🔒Authentication

All protected endpoints require a Bearer token in the Authorization header:
```
Authorization: Bearer <your_access_token>
```
Use the **Authorize** button above to set this for all requests in Swagger UI.

---

## 🛡️Rate Limits

| Endpoint | Limit |
|---|---|
| `POST /auth/login` | 5 requests / 60 seconds |
| `POST /auth/register` | 3 requests / 60 seconds |
| `POST /auth/forgot-password` | 3 requests / 300 seconds |
| `POST /auth/2fa/verify` | 5 requests / 60 seconds |
| `POST /auth/resend-verification` | 3 requests / 300 seconds |

Rate limited responses return **HTTP 429** with a `Retry-After` header.

---

## ❌Error Response Format

All errors follow this consistent shape:
```json
{
  "status": "error",
  "message": "Human readable description",
  "error_code": "MACHINE_READABLE_CODE",
  "details": null
}
```

## ✔️Success Response Format

All successful responses follow this shape:
```json
{
  "status": "success",
  "message": "Description of what happened",
  "data": { ... }
}
```
        """,
        routes=app.routes,
        tags=[
            {
                "name": "Health",
                "description": "Service health and dependency status checks.",
            },
            {
                "name": "Authentication",
                "description": (
                    "Core auth flows: register, verify email, login, "
                    "logout, and token refresh. Start here."
                ),
            },
            {
                "name": "Password Management",
                "description": (
                    "Forgot password (sends reset email), "
                    "reset password (uses token from email), "
                    "and change password (authenticated users)."
                ),
            },
            {
                "name": "OAuth",
                "description": (
                    "Social login via Google and GitHub. "
                    "Navigate your browser to the GET endpoints — "
                    "they redirect to the provider's consent screen. "
                    "Existing accounts are linked automatically by email."
                ),
            },
            {
                "name": "Two-Factor Auth",
                "description": (
                    "TOTP-based 2FA. Enable with /2fa/enable (get QR code), "
                    "confirm with /2fa/confirm (prove you scanned it), "
                    "complete 2FA login with /2fa/verify."
                ),
            },
            {
                "name": "Users",
                "description": (
                    "Authenticated user profile management. "
                    "View and update your own profile."
                ),
            },
            {
                "name": "Sessions",
                "description": (
                    "View all active login sessions across your devices. "
                    "Revoke individual sessions to remote-logout a device."
                ),
            },
            {
                "name": "Admin",
                "description": (
                    "User and role management. Requires the `admin` role. "
                    "List/search users, update roles, activate/deactivate accounts, "
                    "view and force-revoke user sessions."
                ),
            },
        ],
    )

    # ── Bearer token auth scheme ──────────────────────────────────
    # Makes the Authorize button appear in Swagger UI
    schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
            "description": (
                "JWT access token from POST /auth/login. "
                "Paste just the token — the 'Bearer ' prefix is added automatically."
            ),
        }
    }

    # Apply BearerAuth globally as the default security requirement
    schema["security"] = [{"BearerAuth": []}]

    app.openapi_schema = schema
    return app.openapi_schema