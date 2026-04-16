# 🛡️ AuthShield

<div align="center">

![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi)
![Python](https://img.shields.io/badge/python-3.12-blue.svg?style=for-the-badge&logo=python&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-316192?style=for-the-badge&logo=postgresql&logoColor=white)
![Redis](https://img.shields.io/badge/Redis-DC382D?style=for-the-badge&logo=redis&logoColor=white)
![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?style=for-the-badge&logo=docker&logoColor=white)

**A production-ready, standalone authentication microservice — register, login, OAuth 2.0, TOTP 2FA, RBAC, session management, and Redis rate limiting. Deploy once. Plug into every future project.**

[Features](#-features) • [Quick Start](#-getting-started) • [API Endpoints](#-api-endpoints) • [Integration Guide](#-plugging-into-your-project) • [Docker](#-docker--production) • [Tests](#-running-tests)

</div>

---

## 📖 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Tech Stack](#-tech-stack)
- [Live Demo](#-live-demo)
- [Project Structure](#-project-structure)
- [Getting Started](#-getting-started)
  - [Prerequisites](#prerequisites)
  - [Local Setup](#local-setup)
  - [Docker Setup](#-docker--production)
- [Environment Variables](#-environment-variables)
- [Database Schema](#-database-schema)
- [API Endpoints](#-api-endpoints)
- [End-to-End Flow Testing](#-end-to-end-flow-testing)
- [Running Tests](#-running-tests)
- [Plugging Into Your Project](#-plugging-into-your-project)
- [Security Design](#-security-design)
- [Deployment Checklist](#-deployment-checklist)
- [Contributing](#-contributing)

---

## 🌟 Overview

**AuthShield** is a complete, standalone authentication microservice you build once and reuse across every project. It handles everything auth — registration, email verification, JWT token lifecycle, OAuth 2.0 social login, TOTP two-factor authentication, role-based access control, session management, and rate limiting — so your application services never have to implement any of it again.

Downstream services share one `JWT_SECRET_KEY`, validate JWTs **locally with zero runtime calls to AuthShield per request**, and store the `user_id` UUID from the token as a foreign key in their own databases.

### Why AuthShield?

- ✅ **Standalone** — one deployed service handles auth for any number of projects
- ✅ **Zero auth code in your apps** — a 40-line `auth.py` is all your downstream service needs
- ✅ **Production-hardened** — bcrypt, token rotation with theft detection, sliding-window rate limits, security headers on every response
- ✅ **48 integration tests** — real PostgreSQL and Redis, no infrastructure mocks
- ✅ **Full OAuth 2.0** — Google and GitHub with CSRF protection and account linking
- ✅ **TOTP 2FA** — Google Authenticator / Authy compatible, QR code setup flow
- ✅ **Complete session control** — list and revoke individual sessions per device
- ✅ **Structured logging** — JSON logs ready for Datadog, CloudWatch, or Papertrail

---

## ✨ Features

### 🔐 Authentication & Tokens
- **JWT access tokens** (15-minute TTL) + opaque refresh tokens (7-day TTL)
- **Refresh token rotation** — every use issues a new pair and invalidates the old one
- **Reuse detection** — using a rotated token revokes the entire token family (theft signal — attacker and victim both logged out)
- **Redis blacklist** — `POST /auth/logout` takes effect on the very next request, not at natural JWT expiry
- **Email verification** required before first login, with resend endpoint

### 🌐 OAuth 2.0
- **Google** and **GitHub** sign-in via Authorization Code Flow
- **CSRF protection** — single-use state tokens stored in Redis; replayed callbacks rejected
- **Account linking** — OAuth login to an existing email/password account automatically merges them
- **Auto-verified** — OAuth users skip the email verification step entirely

### 🔑 Two-Factor Authentication (TOTP)
- QR code PNG + raw secret returned on setup — scan with any TOTP app
- Single-use temporary token bridges the `login → TOTP verify` step (5-minute TTL)
- Disabling 2FA requires a valid current TOTP code (prevents accidental lockout)
- ±30-second clock skew tolerated (`valid_window=1` in pyotp)

### 👥 Role-Based Access Control (RBAC)
- Three built-in roles: `user`, `moderator`, `admin`
- Roles embedded in the JWT — your services check them with zero database calls
- Admin endpoints protected with a `require_roles(["admin"])` dependency
- Admin cannot remove their own admin role (last-admin lockout prevention)

### 📱 Session Management
- Every login creates a tracked session recording IP address, device info, and timestamps
- List all active sessions — current session flagged with `is_current: true`
- Revoke any specific session — remote sessions kill the refresh token; revoking the current session immediately blacklists the access token
- Admin can revoke all sessions for any user (used on account deactivation)

### 🚦 Rate Limiting
- Redis **sliding-window** algorithm — no fixed-window boundary to exploit
- Per-IP limits on all sensitive endpoints
- `Retry-After`, `X-RateLimit-Limit`, and `X-RateLimit-Window` headers on every 429 response

### 🔒 Security Headers (every response)
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Strict-Transport-Security` + `Content-Security-Policy` in production mode
- `Server` header stripped

### 🔑 Password Management
- bcrypt hashing (12 rounds, ~250 ms per hash — brute-force resistant)
- Forgot/reset flow — time-limited single-use tokens via Redis; successful reset revokes all sessions
- Change password — requires current password, rejects same-as-current
- Email enumeration prevention — `/forgot-password` always returns `200` regardless of whether the email exists

---

## 🛠️ Tech Stack

### Backend
- **[FastAPI](https://fastapi.tiangolo.com/)** — async HTTP framework with automatic OpenAPI docs
- **[Uvicorn](https://www.uvicorn.org/)** — ASGI server (4 workers in production)

### Database
- **[PostgreSQL 15](https://www.postgresql.org/)** — users, roles, sessions, tokens, login audit log
- **[SQLAlchemy 2.0](https://www.sqlalchemy.org/)** — async ORM with relationship loading
- **[Alembic](https://alembic.sqlalchemy.org/)** — version-controlled schema migrations
- **[asyncpg](https://github.com/MagicStack/asyncpg)** — fastest async PostgreSQL driver for Python

### Cache & State
- **[Redis 7](https://redis.io/)** — token blacklist, rate limit windows, 2FA temp tokens, OAuth CSRF state, password reset tokens, email verification tokens

### Authentication & Security
- **[PyJWT](https://pyjwt.readthedocs.io/)** — JWT encode/decode (HS256)
- **[bcrypt](https://pypi.org/project/bcrypt/)** — password hashing (12 rounds)
- **[pyotp](https://pyauth.github.io/pyotp/)** — TOTP generation and verification
- **[qrcode](https://github.com/lincolnloop/python-qrcode)** + **[Pillow](https://pillow.readthedocs.io/)** — QR code PNG generation for 2FA setup
- **[httpx](https://www.python-httpx.org/)** — async HTTP for OAuth token exchange with Google/GitHub

### Validation & Configuration
- **[Pydantic v2](https://docs.pydantic.dev/)** — request/response schema validation, typed settings
- **[pydantic-settings](https://docs.pydantic.dev/latest/concepts/pydantic_settings/)** — typed environment variable loading with `.env` support

### Observability
- **[structlog](https://www.structlog.org/)** — JSON-structured logs ready for production log aggregators

### Testing
- **[pytest](https://pytest.org/)** + **[pytest-asyncio](https://pytest-asyncio.readthedocs.io/)** — async test suite (48 tests)
- **[httpx](https://www.python-httpx.org/)** — async test client via `ASGITransport`
- Real PostgreSQL and Redis — no infrastructure mocks; integration bugs that mocks hide are caught here

---

## 🌐 Live Demo

### API Base URL
```
https://authshield-31lz.onrender.com/docs
```

### Interactive Documentation
- **Swagger UI**: https://authshield-31lz.onrender.com/docs
- **ReDoc**: https://authshield-31lz.onrender.com/redoc

### Health Check
```bash
curl https://authshield-31lz.onrender.com/api/v1/health
# {"status":"healthy","database":"ok","redis":"ok","version":"1.0.0"}
```

### Quick Test
```bash
# Register
curl -X POST https://authshield-31lz.onrender.com/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"TestPass123!","full_name":"Jane Doe"}'

# Login (after verifying email)
curl -X POST https://authshield-31lz.onrender.com/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"TestPass123!"}'
```

---

## 📁 Project Structure

```
authshield/
├── app/
│   ├── main.py                         # App factory, middleware, exception handlers
│   ├── config.py                       # Typed settings via pydantic-settings
│   │
│   ├── api/v1/endpoints/               # Route handlers (thin — delegate to services)
│   │   ├── auth.py                     # Register, login, refresh, logout, verify-email
│   │   ├── oauth.py                    # Google + GitHub OAuth flows + callbacks
│   │   ├── two_factor.py               # 2FA enable, confirm, verify, disable
│   │   ├── sessions.py                 # List sessions, revoke session
│   │   ├── users.py                    # GET /users/me, PATCH /users/me
│   │   └── admin.py                    # Admin user listing, roles, status management
│   │
│   ├── core/
│   │   ├── security.py                 # JWT encode/decode, bcrypt hash/verify
│   │   ├── rate_limiter.py             # Redis sliding-window rate limiter
│   │   ├── exceptions.py               # Custom exception hierarchy + error codes
│   │   └── openapi.py                  # Custom OpenAPI schema (Swagger branding)
│   │
│   ├── db/
│   │   ├── session.py                  # SQLAlchemy async engine + get_db dependency
│   │   ├── redis.py                    # Redis connection pool + get_redis dependency
│   │   └── base.py                     # SQLAlchemy declarative base
│   │
│   ├── middleware/
│   │   └── security.py                 # Injects security headers on every response
│   │
│   ├── models/                         # SQLAlchemy ORM models
│   │   ├── user.py                     # User (email, password_hash, OAuth fields, 2FA secret)
│   │   ├── role.py                     # Role (name, description)
│   │   ├── user_role.py                # Many-to-many junction table
│   │   ├── refresh_token.py            # Token (hash, family_id, rotation chain)
│   │   ├── session.py                  # Session (IP, device, is_active)
│   │   └── login_history.py            # Immutable audit log (append-only)
│   │
│   ├── repositories/                   # DB query logic — no business logic here
│   │   ├── user_repository.py
│   │   ├── role_repository.py
│   │   ├── token_repository.py
│   │   └── session_repository.py
│   │
│   ├── schemas/                        # Pydantic request/response models
│   │   ├── auth.py                     # RegisterRequest, LoginRequest, TokenResponse
│   │   ├── user.py                     # UserResponse, UserUpdateRequest
│   │   ├── admin.py                    # AdminUserResponse, RoleUpdateRequest
│   │   ├── oauth.py                    # OAuthCallbackResponse
│   │   ├── two_factor.py               # TwoFactorSetupResponse, TwoFactorVerifyRequest
│   │   └── common.py                   # StandardResponse[T] wrapper
│   │
│   └── services/                       # Business logic layer
│       ├── auth_service.py             # Registration, login, logout, verification, refresh
│       ├── oauth_service.py            # Google + GitHub token exchange and user linking
│       ├── totp_service.py             # 2FA setup, confirmation, login verify, disable
│       ├── session_service.py          # Session listing and targeted revocation
│       ├── password_service.py         # Forgot/reset/change password flows
│       └── admin_service.py            # User listing, role updates, status management
│
├── alembic/                            # Database migrations
│   └── versions/                       # One file per schema change
│
├── tests/
│   ├── conftest.py                     # Fixtures: db (transaction rollback), client,
│   │                                   #           regular_user, admin_user, rate_limit_client
│   ├── test_auth.py                    # 18 tests — registration, verification, login, refresh, logout
│   ├── test_passwords.py               #  7 tests — forgot, reset, change password
│   ├── test_sessions.py                #  7 tests — listing, revocation, ownership checks
│   ├── test_admin.py                   #  9 tests — RBAC enforcement, user management
│   └── test_rate_limiting.py           #  3 tests — real rate limiter (bypassed in other tests)
│
├── nginx/
│   └── nginx.conf                      # HTTPS, TLS 1.3, OCSP stapling, proxy config
│
├── scripts/
│   └── seed_roles.py                   # Seeds user / moderator / admin roles
│
├── Dockerfile                          # Multi-stage build (~180 MB final image)
├── docker-compose.yml                  # authshield + postgres + redis, with health checks
├── .env.example                        # All environment variables documented
├── alembic.ini                         # Alembic configuration
├── pytest.ini                          # pytest + asyncio config
├── requirements.txt                    # Python dependencies
└── README.md                           # This file
```

---

## 📚 API Documentation

### Base URL
```
http://localhost:8000/api/v1
```

### Authentication
All protected endpoints require a JWT Bearer token in the `Authorization` header:
```
Authorization: Bearer <your_access_token>
```

### Standard Response Format

**Success:**
```json
{
  "status": "success",
  "message": "Operation successful",
  "data": { ... }
}
```

**Error:**
```json
{
  "status": "error",
  "error_code": "AUTH_INVALID_CREDENTIALS",
  "message": "Invalid email or password"
}
```

### Rate Limit Headers

| Header | Description |
|---|---|
| `X-RateLimit-Limit` | Max requests allowed in the window |
| `X-RateLimit-Window` | Window size in seconds |
| `Retry-After` | Seconds until the limit resets (on 429 only) |

---

## 🔌 API Endpoints

### 🔐 Authentication (`/auth`)

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/auth/register` | — | Register with email + password |
| `POST` | `/auth/verify-email` | — | Verify email with token from inbox |
| `POST` | `/auth/resend-verification` | — | Re-send verification email |
| `POST` | `/auth/login` | — | Login — returns access + refresh tokens |
| `POST` | `/auth/refresh` | — | Rotate refresh token — returns new pair |
| `POST` | `/auth/logout` | Bearer | Revoke current session |
| `POST` | `/auth/logout-all` | Bearer | Revoke all sessions on all devices |

<details>
<summary><b>📋 Authentication Examples</b></summary>

**Register:**
```bash
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "StrongPass123!",
    "full_name": "Jane Doe"
  }'
```
```json
{
  "status": "success",
  "message": "Registration successful. Please verify your email.",
  "data": {
    "user_id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com"
  }
}
```

**Login:**
```bash
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "StrongPass123!"}'
```
```json
{
  "status": "success",
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIs...",
    "refresh_token": "rt_a1b2c3d4e5f6...",
    "token_type": "Bearer",
    "expires_in": 900
  }
}
```

**Refresh Token:**
```bash
curl -X POST http://localhost:8000/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "rt_a1b2c3d4e5f6..."}'
# Old refresh_token is permanently invalidated — save the new pair
```

**Logout:**
```bash
curl -X POST http://localhost:8000/api/v1/auth/logout \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIs..." \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "rt_a1b2c3d4e5f6..."}'
# Access token immediately blacklisted — 401 on very next request
```

</details>

---

### 🔑 Password Management (`/auth`)

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/auth/forgot-password` | — | Send reset email (always returns 200) |
| `POST` | `/auth/reset-password` | — | Reset password with emailed token |
| `POST` | `/auth/change-password` | Bearer | Change password while authenticated |

<details>
<summary><b>📋 Password Examples</b></summary>

**Forgot Password:**
```bash
curl -X POST http://localhost:8000/api/v1/auth/forgot-password \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com"}'
# Always returns 200 regardless of whether the email exists — prevents enumeration
```

**Reset Password:**
```bash
curl -X POST http://localhost:8000/api/v1/auth/reset-password \
  -H "Content-Type: application/json" \
  -d '{
    "token": "token-copied-from-email",
    "new_password": "NewStrongPass456!"
  }'
# All existing sessions are revoked on success
```

**Change Password (authenticated):**
```bash
curl -X POST http://localhost:8000/api/v1/auth/change-password \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "current_password": "OldPass123!",
    "new_password": "NewPass456!"
  }'
# Returns 400 AUTH_SAME_PASSWORD if new == current
```

</details>

---

### 🌐 OAuth 2.0 (`/auth/oauth`)

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/auth/oauth/google` | Redirect browser to Google sign-in |
| `GET` | `/auth/oauth/google/callback` | Google redirect callback (handled internally) |
| `GET` | `/auth/oauth/github` | Redirect browser to GitHub sign-in |
| `GET` | `/auth/oauth/github/callback` | GitHub redirect callback (handled internally) |

<details>
<summary><b>📋 OAuth Flow</b></summary>

**Step 1 — Navigate the browser (full-page redirect, not a fetch call):**
```
GET http://localhost:8000/api/v1/auth/oauth/google
→ 302 to Google consent screen
```

**Step 2 — User approves → Google calls the callback:**
```
GET /auth/oauth/google/callback?code=xxx&state=yyy
```

**Step 3 — AuthShield returns tokens:**
```json
{
  "status": "success",
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIs...",
    "refresh_token": "rt_a1b2c3d4...",
    "token_type": "Bearer",
    "is_new_user": true
  }
}
```

> **Account linking**: If the OAuth email already exists in the database from a password registration, it is linked automatically. The user can then sign in via either method.

> **New user**: No email verification required — the OAuth provider already verified the email.

</details>

---

### 🔑 Two-Factor Authentication (`/auth/2fa`)

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/auth/2fa/enable` | Bearer | Begin 2FA setup — returns QR code and secret |
| `POST` | `/auth/2fa/confirm` | Bearer | Confirm 2FA with the first code from the app |
| `POST` | `/auth/2fa/verify` | — | Complete the 2FA login step with temp token |
| `POST` | `/auth/2fa/disable` | Bearer | Disable 2FA (requires valid current TOTP code) |

<details>
<summary><b>📋 2FA Flow</b></summary>

**Step 1 — Enable:**
```bash
curl -X POST http://localhost:8000/api/v1/auth/2fa/enable \
  -H "Authorization: Bearer YOUR_TOKEN"
```
```json
{
  "data": {
    "secret": "JBSWY3DPEHPK3PXP",
    "qr_code": "data:image/png;base64,iVBORw0KGgo...",
    "qr_uri": "otpauth://totp/AuthShield:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=AuthShield"
  }
}
```

**Step 2 — Scan QR code with Google Authenticator or Authy, then confirm:**
```bash
curl -X POST http://localhost:8000/api/v1/auth/2fa/confirm \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"code": "123456"}'
```

**Step 3 — Login flow once 2FA is active:**
```bash
# POST /auth/login now returns 403 instead of tokens:
{
  "error_code": "AUTH_2FA_REQUIRED",
  "details": { "temp_token": "tmp_abc123..." }
}

# Complete login with the TOTP code:
curl -X POST http://localhost:8000/api/v1/auth/2fa/verify \
  -H "Content-Type: application/json" \
  -d '{"temp_token": "tmp_abc123...", "code": "654321"}'
# Returns full access_token + refresh_token
```

</details>

---

### 👤 User Profile (`/users`)

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/users/me` | Bearer | Get own profile, roles, and account status |
| `PATCH` | `/users/me` | Bearer | Update full name or email |

<details>
<summary><b>📋 Profile Examples</b></summary>

**Get Profile:**
```bash
curl http://localhost:8000/api/v1/users/me \
  -H "Authorization: Bearer YOUR_TOKEN"
```
```json
{
  "data": {
    "user_id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "full_name": "Jane Doe",
    "roles": ["user"],
    "is_verified": true,
    "is_active": true,
    "is_2fa_enabled": false,
    "oauth_provider": null,
    "avatar_url": null,
    "created_at": "2025-03-01T10:00:00Z",
    "updated_at": "2025-03-01T10:00:00Z"
  }
}
```

**Update Profile:**
```bash
curl -X PATCH http://localhost:8000/api/v1/users/me \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"full_name": "Jane Updated Doe"}'
```

</details>

---

### 📱 Sessions (`/sessions`)

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/sessions` | Bearer | List all active sessions |
| `DELETE` | `/sessions/{id}` | Bearer | Revoke a specific session |

<details>
<summary><b>📋 Session Examples</b></summary>

**List Sessions:**
```bash
curl http://localhost:8000/api/v1/sessions \
  -H "Authorization: Bearer YOUR_TOKEN"
```
```json
{
  "data": {
    "sessions": [
      {
        "id": "aaa-111",
        "ip_address": "192.168.1.1",
        "device_info": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)...",
        "created_at": "2025-03-01T08:00:00Z",
        "last_used_at": "2025-03-01T10:30:00Z",
        "is_current": true
      },
      {
        "id": "bbb-222",
        "ip_address": "10.0.0.5",
        "device_info": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0)...",
        "created_at": "2025-02-28T20:00:00Z",
        "last_used_at": "2025-03-01T09:15:00Z",
        "is_current": false
      }
    ],
    "total": 2
  }
}
```

**Revoke a Session:**
```bash
curl -X DELETE http://localhost:8000/api/v1/sessions/bbb-222 \
  -H "Authorization: Bearer YOUR_TOKEN"
# Remote session → refresh token killed
# Current session → access token immediately blacklisted in Redis
```

</details>

---

### 🔧 Admin (`/admin`) — requires `admin` role

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/admin/users` | Admin | List all users (paginated + searchable) |
| `GET` | `/admin/users/{id}` | Admin | Get full user details |
| `PATCH` | `/admin/users/{id}/roles` | Admin | Replace user's entire role set |
| `PATCH` | `/admin/users/{id}/status` | Admin | Activate or deactivate an account |
| `GET` | `/admin/users/{id}/sessions` | Admin | View all sessions for a user |
| `DELETE` | `/admin/users/{id}/sessions` | Admin | Revoke all sessions for a user |

<details>
<summary><b>📋 Admin Examples</b></summary>

**List Users (with search):**
```bash
curl "http://localhost:8000/api/v1/admin/users?search=jane&limit=20&skip=0" \
  -H "Authorization: Bearer ADMIN_TOKEN"
```

**Update Roles:**
```bash
curl -X PATCH http://localhost:8000/api/v1/admin/users/USER_ID/roles \
  -H "Authorization: Bearer ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"roles": ["user", "moderator"]}'
# Admin cannot remove their own admin role → 400 ADMIN_CANNOT_REMOVE_OWN_ROLE
```

**Deactivate Account:**
```bash
curl -X PATCH http://localhost:8000/api/v1/admin/users/USER_ID/status \
  -H "Authorization: Bearer ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"is_active": false}'
# Immediately revokes ALL sessions and tokens for that user
```

</details>

---

### 📊 Health

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/health` | — | Live connectivity check for DB and Redis |

```bash
curl http://localhost:8000/api/v1/health
```
```json
{
  "status": "healthy",
  "database": "ok",
  "redis": "ok",
  "version": "1.0.0"
}
```

---

## 🚦 Rate Limits

| Endpoint | Limit | Window |
|---|---|---|
| `POST /auth/login` | 5 requests | 60 s |
| `POST /auth/register` | 3 requests | 60 s |
| `POST /auth/forgot-password` | 3 requests | 5 min |
| `POST /auth/2fa/verify` | 5 requests | 60 s |
| `POST /auth/resend-verification` | 3 requests | 5 min |

**Algorithm**: Redis sorted sets with a sliding window — unlike token-bucket or fixed-window implementations, there is no clock boundary to exploit. Keys expire automatically; no cleanup job needed.

---

## 🚀 Getting Started

### Prerequisites

- **Python 3.12+**
- **PostgreSQL 15+**
- **Redis 7+**
- **Git**
- **Docker**

---

### Local Setup

#### 1️⃣ Clone the repository
```bash
git clone https://github.com/ravigupta97/authshield.git
cd authshield
```

#### 2️⃣ Create virtual environment

**Windows (PowerShell):**
```powershell
python -m venv venv
venv\Scripts\activate
```

**macOS / Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
```

#### 3️⃣ Install dependencies
```bash
pip install -r requirements.txt
```

#### 4️⃣ Configure environment
```bash
cp .env.example .env
# Open .env and fill in DATABASE_URL, REDIS_URL, JWT_SECRET_KEY, and SMTP credentials
```

**Generate a secure JWT_SECRET_KEY:**
```powershell
# Windows PowerShell
python -c "import secrets; print(secrets.token_hex(32))"
```
```bash
# macOS / Linux
openssl rand -hex 32
```

#### 5️⃣ Create the database and run migrations

```bash
# Create the database
createdb authshield_db

# Apply all migrations
alembic upgrade head

# Seed default roles: user, moderator, admin
python scripts/seed_roles.py
```

#### 6️⃣ Start the development server
```bash
uvicorn app.main:app --reload --port 8000
```

**Available at:**
- **Swagger UI**: http://localhost:8000/docs — live endpoint testing with Bearer token auth button
- **ReDoc**: http://localhost:8000/redoc
- **Health check**: http://localhost:8000/api/v1/health

---

## 🐳 Docker & Production

### 1️⃣ Configure the environment file
```bash
cp .env.example .env
# Fill ALL values — especially JWT_SECRET_KEY, POSTGRES_PASSWORD, SMTP / OAuth credentials
```

**Generate a secure `JWT_SECRET_KEY`:**
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

### 2️⃣ Build and start all services
```bash
docker-compose up -d --build
```

This starts three containers on an isolated bridge network:

| Container | Image | Role |
|---|---|---|
| `authshield_api` | Built from `Dockerfile` | FastAPI app (Uvicorn) |
| `authshield_postgres` | `postgres:15-alpine` | Database — data in named volume |
| `authshield_redis` | `redis:7-alpine` | Token blacklist, rate limiting, cache |

### 3️⃣ Run migrations and seed roles
```bash
docker-compose exec authshield alembic upgrade head
docker-compose exec authshield python scripts/seed_roles.py
```

### 4️⃣ Verify the deployment
```bash
curl http://localhost:8000/api/v1/health
# {"status":"healthy","database":"ok","redis":"ok","version":"1.0.0"}
```

### Useful Docker Commands
```bash
# Follow live logs
docker-compose logs -f authshield

# Open a shell inside the container
docker-compose exec authshield bash

# Restart a single service
docker-compose restart authshield

# Stop everything (data is preserved in named volumes)
docker-compose down

# Stop and wipe all data volumes (destructive!)
docker-compose down -v
```

---

## 🔧 Environment Variables

| Variable | Example | Notes |
|---|---|---|
| `APP_ENV` | `production` | `development` \| `staging` \| `production` — enables HSTS + CSP in production |
| `JWT_SECRET_KEY` | 64-char hex string | `python -c "import secrets; print(secrets.token_hex(32))"` — never commit |
| `DATABASE_URL` | `postgresql+asyncpg://user:pw@postgres/db` | In Docker, use service name `postgres` |
| `REDIS_URL` | `redis://redis:6379/0` | In Docker, use service name `redis` |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `15` | Keep short in production |
| `REFRESH_TOKEN_EXPIRE_DAYS` | `7` | Balance security vs UX |
| `BCRYPT_ROUNDS` | `12` | Increase to 13–14 for extra security (~500 ms/hash) |
| `GOOGLE_CLIENT_ID` | `xxx.apps.googleusercontent.com` | [Google Cloud Console](https://console.cloud.google.com/apis/credentials) |
| `GOOGLE_CLIENT_SECRET` | `GOCSPX-xxx` | Use secrets manager — never plain `.env` in git |
| `GITHUB_CLIENT_ID` | `Iv1.xxx` | [GitHub Developer Settings](https://github.com/settings/developers) |
| `GITHUB_CLIENT_SECRET` | `xxx` | Use secrets manager |
| `SMTP_HOST` | `smtp.sendgrid.net` | Use SendGrid / SES / Postmark in production |
| `SMTP_PORT` | `587` | |
| `SMTP_USER` | `apikey` | Provider-specific |
| `SMTP_PASSWORD` | `SG.xxx` | Use secrets manager |
| `FRONTEND_URL` | `https://app.yourdomain.com` | Used in email links and OAuth post-callback redirects |
| `ALLOWED_ORIGINS` | `https://app.yourdomain.com` | Comma-separated CORS origins |

See `.env.example` for the complete annotated list.

---

## 🗄️ Database Schema

```
┌──────────────────────────────────────────┐
│                  USERS                   │
├──────────────────────────────────────────┤
│ id              UUID (PK)                │
│ email           unique, indexed          │
│ password_hash   nullable (null=OAuth user)│
│ full_name       string                   │
│ is_active       bool  default true       │
│ is_verified     bool  default false      │
│ oauth_provider  nullable ("google"|"github")│
│ oauth_id        nullable                 │
│ avatar_url      nullable                 │
│ is_2fa_enabled  bool  default false      │
│ totp_secret     nullable (encrypted)     │
│ created_at      timestamp                │
│ updated_at      timestamp                │
└──────────────────┬───────────────────────┘
                   │ 1
        ┌──────────┼──────────────────────────────┐
        │ N        │ N                            │ N
┌───────▼──────┐ ┌─▼────────────────┐  ┌──────────▼──────────┐
│  USER_ROLES  │ │    SESSIONS      │  │   REFRESH_TOKENS    │
├──────────────┤ ├──────────────────┤  ├─────────────────────┤
│ user_id  FK  │ │ id   UUID (PK)   │  │ id        UUID (PK) │
│ role_id  FK  │ │ user_id       FK │  │ token_hash SHA-256  │
└──────┬───────┘ │ ip_address       │  │ user_id   FK        │
       │         │ device_info      │  │ session_id FK       │
       │ N       │ is_active  bool  │  │ family_id  UUID     │◄── rotation chain
┌──────▼──────┐  │ created_at       │  │ is_used    bool     │
│    ROLES    │  │ last_used_at     │  │ is_revoked bool     │
├─────────────┤  └──────────────────┘  │ expires_at          │
│ id  UUID    │                        └─────────────────────┘
│ name string │  ┌────────────────────────────────────────────┐
│ description │  │             LOGIN_HISTORY                  │
└─────────────┘  ├────────────────────────────────────────────┤
                 │ id             UUID (PK)                   │
                 │ user_id        FK  (nullable)              │
                 │ ip_address     string                      │
                 │ status         success | failed            │
                 │ failure_reason nullable                    │
                 │ created_at     timestamp  (append-only)    │
                 └────────────────────────────────────────────┘
```

### Key Design Decisions

| Decision | Why |
|---|---|
| `password_hash` is nullable | OAuth users authenticate via provider — they have no password |
| `token_hash` stores SHA-256, not the raw token | DB breach exposes unusable hashes, not working tokens |
| `family_id` on refresh tokens | Groups a rotation chain — reuse of any token kills the entire family |
| `login_history` is append-only | Provides a tamper-evident audit trail — no updates, no deletes |
| No `users` table in your apps | Downstream services store `user_id` UUID as a FK — AuthShield owns user data |

---

## 🧪 End-to-End Flow Testing

### Full Registration → Login → Refresh Flow
```bash
# 1. Register
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"TestPass123!","full_name":"Test User"}'

# 2. Check Mailtrap for the verification email — copy the token

# 3. Verify email
curl -X POST http://localhost:8000/api/v1/auth/verify-email \
  -H "Content-Type: application/json" \
  -d '{"token": "TOKEN_FROM_EMAIL"}'

# 4. Login — save both tokens
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"TestPass123!"}'

# 5. Call a protected endpoint
curl http://localhost:8000/api/v1/users/me \
  -H "Authorization: Bearer ACCESS_TOKEN"

# 6. Rotate refresh token
curl -X POST http://localhost:8000/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "REFRESH_TOKEN"}'

# 7. Try the old refresh token — expect 401 AUTH_REFRESH_TOKEN_REUSED
#    AND entire token family is revoked (token theft detection)
```

### Edge Cases to Verify

```bash
# Login before email verification → 403 AUTH_EMAIL_NOT_VERIFIED
# Duplicate email registration → 409 AUTH_EMAIL_ALREADY_REGISTERED
# Weak password (no uppercase/digit/special) → 422
# Wrong password → 401 AUTH_INVALID_CREDENTIALS (same message as non-existent email)
# Tampered JWT signature → 401 AUTH_TOKEN_INVALID
# Expired access token → 401 AUTH_TOKEN_EXPIRED
# Logout then use old access token → 401 AUTH_TOKEN_REVOKED
# 6 POSTs to /auth/login → 429 SYS_RATE_LIMIT_EXCEEDED + Retry-After header
# Invalid verification token → 400 AUTH_INVALID_VERIFICATION_TOKEN
# Verification token used twice → 400 on second attempt
# Reset to same password → 400 AUTH_SAME_PASSWORD
# Admin removing own admin role → 400 ADMIN_CANNOT_REMOVE_OWN_ROLE
```

---

## 🧪 Running Tests

```bash
# All 48 tests
pytest tests/ -v

# Specific test file
pytest tests/test_auth.py -v

# Specific test class
pytest tests/test_sessions.py::TestSessionRevocation -v

# Stop on first failure
pytest tests/ -v -x

# With captured stdout (useful for debugging)
pytest tests/ -v -s --tb=short

# Clear Redis rate-limit keys before a run (Windows PowerShell)
redis-cli --scan --pattern "rate:*" | ForEach-Object { redis-cli DEL $_ }
```

### Test Results
```
tests/test_admin.py::TestRBACEnforcement::test_regular_user_cannot_access_admin   PASSED
tests/test_admin.py::TestRBACEnforcement::test_admin_can_list_users                PASSED
tests/test_admin.py::TestUserManagement::test_admin_can_deactivate_user            PASSED
tests/test_admin.py::TestUserManagement::test_admin_cannot_remove_own_admin_role   PASSED
tests/test_auth.py::TestRegistration::test_register_success                        PASSED
tests/test_auth.py::TestEmailVerification::test_verify_email_success               PASSED
tests/test_auth.py::TestLogin::test_login_success                                  PASSED
tests/test_auth.py::TestTokenRefresh::test_refresh_token_rotation                  PASSED
tests/test_auth.py::TestLogout::test_logout_success                                PASSED
tests/test_passwords.py::TestForgotPassword::test_forgot_password_always_returns_200 PASSED
tests/test_sessions.py::TestSessionRevocation::test_revoke_current_session         PASSED
tests/test_rate_limiting.py::TestLoginRateLimit::test_login_rate_limit_enforced    PASSED
... (36 more)

==================== 48 passed in 218.12s ====================
```

### Testing Strategy

| Concern | Approach |
|---|---|
| DB isolation | Each test wraps operations in a transaction that rolls back — no persistent test data |
| Rate limiting | Disabled via `TESTING=true` env var in all tests except `test_rate_limiting.py` |
| Rate limit tests | `rate_limit_client` fixture temporarily unsets `TESTING` to enable real rate limiting |
| Infrastructure | Real PostgreSQL and Redis — integration bugs that mocks hide are caught |
| Windows compat | `WindowsSelectorEventLoopPolicy` set in root `conftest.py` for Redis/asyncio compatibility |

---

## 🔌 Plugging Into Your Project

AuthShield is a standalone service. Your downstream projects need exactly **one file** and **one shared environment variable**.

> 📖 **Full integration guide with multi-framework examples (FastAPI, Flask, Django, Express) and a complete E-Commerce walkthrough:** [INTEGRATION_GUIDE.md](./INTEGRATION_GUIDE.md)

### The Mental Model

```
Your Frontend
    │
    ├── auth requests ──────▶ AuthShield  :8000
    │   (login, register,      (issues + manages JWTs)
    │    OAuth, 2FA, logout)
    │
    └── business requests ──▶ Your API    :8001
        (tasks, orders, etc.)  (validates JWT locally — zero calls to AuthShield)
```

### Step 1 — Copy `auth.py` into every new project

```python
# your_project/auth.py  ← copy verbatim, never changes
import os, jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

SECRET_KEY = os.getenv("SECRET_KEY")   # same value as AuthShield
ALGORITHM  = "HS256"
bearer     = HTTPBearer()

def get_current_user(
    creds: HTTPAuthorizationCredentials = Depends(bearer)
) -> dict:
    try:
        payload = jwt.decode(creds.credentials, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token")
    if payload.get("type") != "access":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not an access token")
    return payload  # {sub, email, roles, session_id, jti, exp}

def require_roles(roles: list[str]):
    """Factory: require at least one of the given roles."""
    def check(user: dict = Depends(get_current_user)) -> dict:
        if not any(r in user["roles"] for r in roles):
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"Requires roles: {roles}")
        return user
    return check
```

### Step 2 — Add one env var to your project

```env
# your_project/.env
SECRET_KEY=same-value-as-authshield   # that's the only AuthShield config needed
```

### Step 3 — Protect your endpoints

```python
from auth import get_current_user, require_roles

# Any authenticated user
@app.get("/tasks")
def list_tasks(user = Depends(get_current_user), db = Depends(get_db)):
    return db.query(Task).filter_by(user_id=user["sub"]).all()
    #                                         ↑ UUID from JWT — FK in your DB

# Admin only
@app.delete("/admin/tasks/{id}")
def delete_any_task(user = Depends(require_roles(["admin"]))):
    ...
```

### Step 4 — Your database schema (no users table)

```python
class Task(Base):
    __tablename__ = "tasks"
    id      = Column(UUID, primary_key=True, default=uuid4)
    user_id = Column(UUID, nullable=False, index=True)
    # ↑ This is user["sub"] from the JWT.
    # No FK constraint to a users table — AuthShield owns users entirely.
    title   = Column(String, nullable=False)
```

### JWT Payload Reference

```json
{
  "sub":        "550e8400-e29b-41d4-a716-446655440000",
  "email":      "user@example.com",
  "roles":      ["user"],
  "session_id": "abc-123",
  "jti":        "unique-token-id",
  "type":       "access",
  "iat":        1700000000,
  "exp":        1700000900
}
```

---

## 🔒 Security Design

| Decision | Rationale |
|---|---|
| 15-minute access token TTL | Stolen token window is ≤15 minutes |
| Refresh tokens stored as SHA-256 hash | DB breach exposes unusable hashes — not working tokens |
| Token family revocation on reuse | Reuse means possible theft — revoking the family kicks the attacker AND forces the victim to re-login, alerting them |
| Redis blacklist on logout | Immediate effect — no gap between logout and natural token expiry |
| bcrypt 12 rounds (~250 ms/hash) | Brute-forcing 10M passwords would take ~29 days on a 10-GPU rig |
| Single-use OAuth state tokens in Redis | Replayed OAuth callbacks are rejected (CSRF hardening) |
| Password reset revokes all sessions | If an attacker triggered the reset, they are kicked on completion |
| Forgot-password always returns 200 | Prevents discovering which emails are registered |
| Admin cannot remove own admin role | Prevents last-admin lockout |
| Sliding-window rate limits | No fixed-window boundary to exploit |
| Security headers on every response | Mitigates clickjacking, MIME sniffing, XSS, and referrer leakage |

---

## ✅ Deployment Checklist

### Before First Deploy
- [ ] Generate `SECRET_KEY` — `openssl rand -hex 32`
- [ ] Set `ENVIRONMENT=production`
- [ ] Configure production SMTP (SendGrid / AWS SES / Postmark)
- [ ] Update Google and GitHub OAuth redirect URIs to your production domain
- [ ] Obtain SSL certificate (Let's Encrypt / Certbot — free)
- [ ] Set strong `POSTGRES_PASSWORD` and `REDIS_PASSWORD`

### Deploy
- [ ] `docker-compose up -d --build`
- [ ] `docker-compose exec api alembic upgrade head`
- [ ] `docker-compose exec api python scripts/seed_roles.py`
- [ ] `curl https://auth.yourdomain.com/api/v1/health` → `{"status":"healthy"}`

### Post-Deploy Smoke Tests
- [ ] `GET /docs` returns 404 *(Swagger hidden in production)*
- [ ] Security headers present on all responses
- [ ] 6th login attempt in 60 s returns 429 with `Retry-After` header
- [ ] Registration email arrives in inbox
- [ ] Full Google OAuth flow completes on production domain

### Monitoring
- [ ] Ship JSON logs to Datadog / CloudWatch / Papertrail
- [ ] Alert on elevated `AUTH_INVALID_CREDENTIALS` rate — brute-force signal
- [ ] Alert on `AUTH_REFRESH_TOKEN_REUSED` — possible token theft
- [ ] Monitor Redis memory (rate-limit keys accumulate under sustained attack)
- [ ] Schedule `login_history` table cleanup (grows unbounded)

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. **Fork the repository**
2. **Create a feature branch:**
```bash
git checkout -b feature/amazing-feature
```
3. **Make your changes and commit:**
```bash
git commit -m "feat: add amazing feature"
```
4. **Push to your fork:**
```bash
git push origin feature/amazing-feature
```
5. **Open a Pull Request**

### Contribution Guidelines
- Follow PEP 8 style guide
- Add tests for all new features — maintain 48+ passing
- Keep commits atomic and descriptive (`feat:`, `fix:`, `test:`, `docs:`)
- Update this README if endpoints or env vars change

---

## 👨‍💻 Author

**Ravi Gupta**

- GitHub: [@ravigupta97](https://github.com/ravigupta97)
- LinkedIn: [Ravi Gupta](https://www.linkedin.com/in/ravigupta97)
- Email: gupta_ravi@outlook.in

---

## 🙏 Acknowledgments

- [FastAPI](https://fastapi.tiangolo.com/) — outstanding async web framework
- [SQLAlchemy](https://www.sqlalchemy.org/) — powerful async ORM
- [Redis](https://redis.io/) — the backbone of blacklisting, rate limiting, and OAuth state
- [pyotp](https://pyauth.github.io/pyotp/) — clean, standards-compliant TOTP implementation
- [structlog](https://www.structlog.org/) — JSON-structured logging done right

---

## 📞 Support

- 💬 **Issues**: [GitHub Issues](https://github.com/ravigupta97/authshield/issues)
- 📖 **Swagger Docs**: http://localhost:8000/docs

---

<div align="center">

**Built using FastAPI, PostgreSQL, and Redis**

[⬆ Back to Top](#️-authshield)

</div>
