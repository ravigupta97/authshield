# 🔌 AuthShield Integration Guide

> **One service. One secret. Zero auth code in your apps.**
>
> This guide walks you through plugging any new service into AuthShield using an **E-Commerce API** as the example. Code samples are provided for **FastAPI (Python)**, **Flask (Python)**, **Django REST Framework**, and **Express (Node.js / TypeScript)** — pick the one that fits your stack.

---

## The Mental Model

Think of AuthShield as a **bouncer** that stands outside every club you ever open. It issues wristbands (JWTs). Your clubs check wristbands at the door — they never call the bouncer again per entry.

```
Browser / Mobile App
        │
        ├── auth requests ──────▶  AuthShield  :8000
        │   register, login,        issues & manages JWTs
        │   OAuth, 2FA, logout       
        │
        └── business requests ──▶  Your E-Commerce API  :8001
            orders, products,       checks JWT locally
            cart, payments          zero calls to AuthShield
```

**The only shared secret is `SECRET_KEY`.** Your downstream service never makes runtime HTTP calls to AuthShield; it validates the JWT cryptographically in ~1 ms.

---

## Contents

1. [Run AuthShield](#1-run-authshield)
2. [Create Your Project](#2-create-your-project)
3. [The Auth Module — Pick Your Framework](#3-the-auth-module--pick-your-framework)
   - [FastAPI (Python)](#fastapi-python)
   - [Flask (Python)](#flask-python)
   - [Django REST Framework](#django-rest-framework)
   - [Express / TypeScript (Node.js)](#express--typescript-nodejs)
4. [Database Schema — No Users Table](#4-database-schema--no-users-table)
5. [Wire Auth Into Your Endpoints](#5-wire-auth-into-your-endpoints)
6. [Environment Variables](#6-environment-variables)
7. [Docker Compose — Running Both Services](#7-docker-compose--running-both-services)
8. [Frontend Token Flow](#8-frontend-token-flow)
9. [Reusable TypeScript Token Manager](#9-reusable-typescript-token-manager)
10. [Adding a Third Service Later](#10-adding-a-third-service-later)
11. [What You Never Build Again](#11-what-you-never-build-again)

---

## 1. Run AuthShield

```bash
git clone https://github.com/ravigupta97/authshield.git
cd authshield

cp .env.example .env
# Fill in: SECRET_KEY, DATABASE_URL, REDIS_URL, SMTP_*

docker-compose up -d

# Verify
curl http://localhost:8000/api/v1/health
# {"status":"healthy","database":"ok","redis":"ok","version":"1.0.0"}
```

Note your `JWT_SECRET_KEY` — you will paste it into every future service's `.env` as `JWT_SECRET_KEY`. That is the **only** value any downstream service needs from AuthShield.

---

## 2. Create Your Project

```bash
mkdir ecommerce-api && cd ecommerce-api
```

The directory structure is the same regardless of framework:

```
ecommerce-api/
├── auth.py / auth.ts          ← the ONE file from AuthShield you copy
├── main.py / app.py / app.ts  ← your API
├── models.py / models.ts      ← your DB models (no users table)
├── database.py / db.ts        ← DB connection
├── .env                       ← DATABASE_URL + SECRET_KEY only
└── requirements.txt / package.json
```

---

## 3. The Auth Module — Pick Your Framework

This is the **only** AuthShield-related file you write. Copy it verbatim into every future service. It never changes regardless of your business domain.

---

### FastAPI (Python)

```python
# auth.py
"""
JWT validation for services backed by AuthShield.

Usage:
    from auth import get_current_user, require_roles

    @app.get("/orders")
    async def list_orders(user = Depends(get_current_user)):
        user_id = user["sub"]    # UUID — use as FK in your DB
        roles   = user["roles"]  # ["user"] | ["user", "admin"]

    @app.delete("/admin/orders/{id}")
    async def delete_order(user = Depends(require_roles(["admin"]))):
        ...
"""

import os
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

SECRET_KEY = os.getenv("SECRET_KEY")  # same value as AuthShield
ALGORITHM  = "HS256"
bearer     = HTTPBearer()


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer),
) -> dict:
    """Validates the JWT. Raises 401 on any failure."""
    try:
        payload = jwt.decode(
            credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM]
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    if payload.get("type") != "access":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Not an access token")

    return payload  # {sub, email, roles, session_id, jti, exp}


def require_roles(roles: list[str]):
    """Factory: enforce at least one of the given roles."""
    def check(user: dict = Depends(get_current_user)) -> dict:
        if not any(r in user["roles"] for r in roles):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of: {roles}",
            )
        return user
    return check
```

Install: `pip install fastapi uvicorn pyjwt`

---

### Flask (Python)

```python
# auth.py
"""
JWT validation decorator for Flask services backed by AuthShield.

Usage:
    from auth import login_required, roles_required

    @app.route("/orders")
    @login_required
    def list_orders(user):
        user_id = user["sub"]

    @app.route("/admin/orders/<id>", methods=["DELETE"])
    @roles_required("admin")
    def delete_order(user, id):
        ...
"""

import os
import jwt
from functools import wraps
from flask import request, jsonify, g

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM  = "HS256"


def _decode_token(authorization: str | None) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise ValueError("Missing or malformed Authorization header")
    token = authorization.split(" ", 1)[1]
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    if payload.get("type") != "access":
        raise ValueError("Not an access token")
    return payload


def login_required(f):
    """Decorator: validates JWT and injects user dict as first positional arg."""
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            user = _decode_token(request.headers.get("Authorization"))
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except (jwt.InvalidTokenError, ValueError) as e:
            return jsonify({"error": str(e)}), 401
        return f(user, *args, **kwargs)
    return decorated


def roles_required(*roles):
    """Decorator factory: enforces at least one role."""
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated(user, *args, **kwargs):
            if not any(r in user["roles"] for r in roles):
                return jsonify({"error": f"Requires one of: {list(roles)}"}), 403
            return f(user, *args, **kwargs)
        return decorated
    return decorator
```

Install: `pip install flask pyjwt`

---

### Django REST Framework

```python
# auth.py
"""
JWT authentication backend for DRF services backed by AuthShield.

Add to settings.py:
    REST_FRAMEWORK = {
        "DEFAULT_AUTHENTICATION_CLASSES": ["auth.AuthShieldAuthentication"],
    }

Usage in views:
    from rest_framework.permissions import IsAuthenticated
    from auth import IsAdmin

    class OrderViewSet(ModelViewSet):
        authentication_classes = [AuthShieldAuthentication]
        permission_classes = [IsAuthenticated]

        def get_queryset(self):
            user_id = self.request.user.id   # UUID from JWT "sub"
            return Order.objects.filter(user_id=user_id)

    class AdminOrderView(APIView):
        permission_classes = [IsAdmin]
"""

import os
import jwt
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.permissions import BasePermission


SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM  = "HS256"


class AuthShieldUser:
    """Lightweight user object wrapping the JWT payload."""
    def __init__(self, payload: dict):
        self.id            = payload["sub"]    # UUID
        self.email         = payload["email"]
        self.roles         = payload["roles"]
        self.is_authenticated = True

    def __str__(self):
        return self.email


class AuthShieldAuthentication(BaseAuthentication):
    def authenticate(self, request):
        header = request.headers.get("Authorization")
        if not header or not header.startswith("Bearer "):
            return None  # Let other authenticators try

        token = header.split(" ", 1)[1]
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed("Token expired")
        except jwt.InvalidTokenError:
            raise AuthenticationFailed("Invalid token")

        if payload.get("type") != "access":
            raise AuthenticationFailed("Not an access token")

        return (AuthShieldUser(payload), token)


class IsAdmin(BasePermission):
    def has_permission(self, request, view):
        return (
            request.user
            and request.user.is_authenticated
            and "admin" in request.user.roles
        )
```

Install: `pip install djangorestframework pyjwt`

---

### Express / TypeScript (Node.js)

```typescript
// src/auth.ts
/**
 * JWT validation middleware for Express services backed by AuthShield.
 *
 * Usage:
 *   import { authenticate, requireRoles } from "./auth";
 *
 *   router.get("/orders", authenticate, async (req, res) => {
 *     const userId = req.user.sub;  // UUID
 *   });
 *
 *   router.delete("/admin/orders/:id",
 *     authenticate,
 *     requireRoles(["admin"]),
 *     async (req, res) => { ... }
 *   );
 */

import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";

const SECRET_KEY = process.env.SECRET_KEY!;
const ALGORITHM  = "HS256" as const;

export interface AuthPayload {
  sub:        string;   // UUID — user identifier
  email:      string;
  roles:      string[];
  session_id: string;
  jti:        string;
  type:       string;
  exp:        number;
}

// Extend Express Request so req.user is typed project-wide
declare global {
  namespace Express {
    interface Request { user: AuthPayload; }
  }
}

export function authenticate(req: Request, res: Response, next: NextFunction) {
  const header = req.headers.authorization;
  if (!header?.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Missing Authorization header" });
  }

  const token = header.slice(7);
  try {
    const payload = jwt.verify(token, SECRET_KEY, { algorithms: [ALGORITHM] }) as AuthPayload;
    if (payload.type !== "access") {
      return res.status(401).json({ error: "Not an access token" });
    }
    req.user = payload;
    next();
  } catch (err: any) {
    const msg = err.name === "TokenExpiredError" ? "Token expired" : "Invalid token";
    return res.status(401).json({ error: msg });
  }
}

export function requireRoles(roles: string[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!roles.some((r) => req.user?.roles.includes(r))) {
      return res.status(403).json({ error: `Requires one of: ${roles}` });
    }
    next();
  };
}
```

Install: `npm install jsonwebtoken && npm install -D @types/jsonwebtoken`

---

## 4. Database Schema — No Users Table

Your service stores only the `user_id` UUID from the JWT. **There is no users table.** AuthShield is the single source of truth for user data.

### SQLAlchemy (Python)

```python
# models.py
import uuid
from sqlalchemy import Column, String, Boolean, Numeric, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from database import Base

class Product(Base):
    __tablename__ = "products"

    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name        = Column(String(255), nullable=False)
    description = Column(String, nullable=True)
    price       = Column(Numeric(10, 2), nullable=False)
    stock       = Column(Numeric, default=0)
    created_at  = Column(DateTime, server_default="now()")


class Order(Base):
    __tablename__ = "orders"

    id         = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id    = Column(UUID(as_uuid=True), nullable=False, index=True)
    # ↑ This is user["sub"] from the JWT payload.
    # No FK to a users table — AuthShield owns user records entirely.
    status     = Column(String, default="pending")  # pending | paid | shipped | cancelled
    total      = Column(Numeric(10, 2), nullable=False)
    created_at = Column(DateTime, server_default="now()")


class OrderItem(Base):
    __tablename__ = "order_items"

    id         = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    order_id   = Column(UUID(as_uuid=True), ForeignKey("orders.id"), nullable=False)
    product_id = Column(UUID(as_uuid=True), ForeignKey("products.id"), nullable=False)
    quantity   = Column(Numeric, nullable=False)
    unit_price = Column(Numeric(10, 2), nullable=False)
```

### Prisma (TypeScript / Node.js)

```prisma
// schema.prisma
model Product {
  id          String   @id @default(uuid())
  name        String
  description String?
  price       Decimal  @db.Decimal(10, 2)
  stock       Int      @default(0)
  createdAt   DateTime @default(now())

  orderItems  OrderItem[]
}

model Order {
  id        String   @id @default(uuid())
  userId    String                          // ← JWT payload "sub"; no User relation
  status    String   @default("pending")   // pending | paid | shipped | cancelled
  total     Decimal  @db.Decimal(10, 2)
  createdAt DateTime @default(now())
  items     OrderItem[]
}

model OrderItem {
  id        String  @id @default(uuid())
  order     Order   @relation(fields: [orderId], references: [id])
  orderId   String
  product   Product @relation(fields: [productId], references: [id])
  productId String
  quantity  Int
  unitPrice Decimal @db.Decimal(10, 2)
}
```

> **Why no FK to a users table?**  
> AuthShield owns the full user lifecycle (create, deactivate, delete). Your service only ever needs the `user_id` UUID to associate records. If AuthShield deletes a user, your service handles orphaned records with soft-delete or a scheduled cleanup job — not a cascading FK constraint.

---

## 5. Wire Auth Into Your Endpoints

### FastAPI example

```python
# main.py
from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from auth import get_current_user, require_roles
from database import get_db
from models import Product, Order, OrderItem
from schemas import OrderCreate, ProductCreate

app = FastAPI(title="E-Commerce API")

# ── Public endpoints ──────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/products")
async def list_products(db: AsyncSession = Depends(get_db)):
    """Anyone can browse products — no auth required."""
    result = await db.execute(select(Product))
    return result.scalars().all()

# ── Authenticated endpoints ───────────────────────────────────────

@app.post("/orders", status_code=201)
async def place_order(
    body: OrderCreate,
    user = Depends(get_current_user),  # ← the only line that adds auth
    db: AsyncSession = Depends(get_db),
):
    order = Order(user_id=user["sub"], total=body.total)
    db.add(order)
    await db.commit()
    return order

@app.get("/orders/my")
async def my_orders(
    user = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Order).where(Order.user_id == user["sub"])
    )
    return result.scalars().all()

# ── Admin-only endpoints ──────────────────────────────────────────

Admin = Depends(require_roles(["admin"]))

@app.post("/products", status_code=201)
async def create_product(
    body: ProductCreate,
    user = Admin,
    db: AsyncSession = Depends(get_db),
):
    product = Product(**body.model_dump())
    db.add(product)
    await db.commit()
    return product

@app.patch("/orders/{order_id}/status")
async def update_order_status(
    order_id: str,
    new_status: str,
    user = Admin,
    db: AsyncSession = Depends(get_db),
):
    order = await db.get(Order, order_id)
    if not order:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Order not found")
    order.status = new_status
    await db.commit()
    return order
```

### Express equivalent

```typescript
// src/routes/orders.ts
import { Router } from "express";
import { authenticate, requireRoles } from "../auth";
import { prisma } from "../db";

const router = Router();

// Public
router.get("/products", async (req, res) => {
  const products = await prisma.product.findMany();
  res.json(products);
});

// Authenticated
router.post("/orders", authenticate, async (req, res) => {
  const userId = req.user.sub;  // UUID from JWT
  const order = await prisma.order.create({
    data: { userId, total: req.body.total, status: "pending" },
  });
  res.status(201).json(order);
});

router.get("/orders/my", authenticate, async (req, res) => {
  const orders = await prisma.order.findMany({
    where: { userId: req.user.sub },
  });
  res.json(orders);
});

// Admin only
router.post(
  "/products",
  authenticate,
  requireRoles(["admin"]),
  async (req, res) => {
    const product = await prisma.product.create({ data: req.body });
    res.status(201).json(product);
  }
);

export default router;
```

---

## 6. Environment Variables

Your new project's `.env` needs **exactly two AuthShield-related values**:

```env
# ecommerce-api/.env

# ── Your project's own database ───────────────────────────────────
DATABASE_URL=postgresql+asyncpg://postgres:password@localhost/ecommerce_db
# or for Node.js / Prisma:
# DATABASE_URL=postgresql://postgres:password@localhost/ecommerce_db

# ── The ONLY value shared with AuthShield ─────────────────────────
# Copy exactly from authshield/.env → JWT_SECRET_KEY
JWT_SECRET_KEY=paste-the-same-value-from-authshield-env-here

# ── Optional: your service config ─────────────────────────────────
PORT=8001
ENVIRONMENT=development
```

That's it. There is no AuthShield base URL, no API key, no client secret. Your service is **fully decoupled** from AuthShield's uptime at request time.

---

## 7. Docker Compose — Running Both Services

Here is a minimal `docker-compose.yml` that runs AuthShield and your E-Commerce API side by side, sharing a single Docker network:

```yaml
# docker-compose.yml (in your workspace root or ecommerce-api/)

version: "3.9"

services:

  # ── Shared infrastructure ──────────────────────────────────────
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: secret
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD", "pg_isready", "-U", "postgres"]
      interval: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      retries: 5

  # ── AuthShield ────────────────────────────────────────────────
  authshield:
    build: ./authshield
    ports:
      - "8000:8000"
    env_file: ./authshield/.env
    environment:
      DATABASE_URL: postgresql+asyncpg://postgres:secret@postgres/authshield_db
      REDIS_URL: redis://redis:6379/0
    depends_on:
      postgres: { condition: service_healthy }
      redis:    { condition: service_healthy }

  # ── Your E-Commerce API ────────────────────────────────────────
  ecommerce:
    build: ./ecommerce-api
    ports:
      - "8001:8001"
    env_file: ./ecommerce-api/.env
    environment:
      DATABASE_URL: postgresql+asyncpg://postgres:secret@postgres/ecommerce_db
      JWT_SECRET_KEY: ${JWT_SECRET_KEY}  # same value as authshield/.env
    depends_on:
      postgres: { condition: service_healthy }
      authshield: { condition: service_started }

volumes:
  postgres_data:
```

> **Tip:** Both services can share the same PostgreSQL instance using different database names (`authshield_db` vs `ecommerce_db`). They never touch each other's tables.

---

## 8. Frontend Token Flow

Here is every request your frontend will ever make, and which service receives it:

```
Step 1 — REGISTER (→ AuthShield)
  POST /api/v1/auth/register
  { "email": "shopper@example.com", "password": "Pass123!", "full_name": "Jane Doe" }

Step 2 — VERIFY EMAIL (→ AuthShield)
  POST /api/v1/auth/verify-email
  { "token": "<token from inbox>" }

Step 3 — LOGIN (→ AuthShield)
  POST /api/v1/auth/login
  { "email": "shopper@example.com", "password": "Pass123!" }
  ← { "access_token": "eyJ...", "refresh_token": "rt_...", "expires_in": 900 }

Step 4 — SHOP (→ Your E-Commerce API)
  GET  /products              (no auth needed)
  POST /orders                Authorization: Bearer <access_token>
  GET  /orders/my             Authorization: Bearer <access_token>

Step 5 — TOKEN EXPIRES after 15 min (→ AuthShield)
  POST /api/v1/auth/refresh
  { "refresh_token": "rt_..." }
  ← { "access_token": "eyJ...(new)", "refresh_token": "rt_...(new)" }
  ⚠️  Save the NEW pair — the old refresh token is invalid immediately.

Step 6 — RETRY (→ Your E-Commerce API)
  POST /orders                Authorization: Bearer <new_access_token>

Step 7 — LOGOUT (→ AuthShield)
  POST /api/v1/auth/logout
  Authorization: Bearer <access_token>
  { "refresh_token": "rt_..." }
  Access token is blacklisted instantly — 401 on very next use.
```

**The rule:** steps involving auth (login, logout, token refresh, register, OAuth, 2FA) go to AuthShield. All business steps go to your API.

---

## 9. Reusable TypeScript Token Manager

Paste this once per frontend project. Works with any AuthShield-backed backend:

```typescript
// src/tokenManager.ts

const AUTHSHIELD_URL = "http://localhost:8000/api/v1";
const ECOMMERCE_URL  = "http://localhost:8001";

let accessToken: string | null = null;

export const auth = {
  /** Call on app start — silently restores session if refresh token is still valid */
  async init(): Promise<boolean> {
    return this.refresh();
  },

  async register(email: string, password: string, fullName: string) {
    const res = await fetch(`${AUTHSHIELD_URL}/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password, full_name: fullName }),
    });
    if (!res.ok) throw await res.json();
    return res.json();
  },

  async login(email: string, password: string) {
    const res = await fetch(`${AUTHSHIELD_URL}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
      credentials: "include",          // stores refresh token as httpOnly cookie
    });
    if (!res.ok) throw await res.json();
    const { data } = await res.json();
    accessToken = data.access_token;  // keep in memory only — never localStorage
  },

  async refresh(): Promise<boolean> {
    const res = await fetch(`${AUTHSHIELD_URL}/auth/refresh`, {
      method: "POST",
      credentials: "include",          // sends the httpOnly cookie automatically
    });
    if (!res.ok) { accessToken = null; return false; }
    const { data } = await res.json();
    accessToken = data.access_token;
    return true;
  },

  async logout() {
    await fetch(`${AUTHSHIELD_URL}/auth/logout`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${accessToken}`,
      },
      credentials: "include",
    });
    accessToken = null;
  },

  /**
   * Use this for ALL calls to your business APIs.
   * Handles token expiry transparently — refreshes and retries once.
   */
  async fetch(url: string, options: RequestInit = {}): Promise<Response> {
    if (!accessToken) {
      const ok = await this.refresh();
      if (!ok) throw new Error("Not authenticated");
    }

    const res = await fetch(url, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        ...options.headers,
        Authorization: `Bearer ${accessToken}`,
      },
    });

    if (res.status === 401) {
      const ok = await this.refresh();
      if (!ok) { window.location.href = "/login"; throw new Error("Session expired"); }
      return this.fetch(url, options);  // retry once with new token
    }

    return res;
  },
};

// ── Usage examples ───────────────────────────────────────────────

// On app start
await auth.init();

// Login
await auth.login("shopper@example.com", "Pass123!");

// Call your E-Commerce API — token management is automatic
const products = await auth.fetch(`${ECOMMERCE_URL}/products`).then(r => r.json());
const order    = await auth.fetch(`${ECOMMERCE_URL}/orders`, {
  method: "POST",
  body: JSON.stringify({ total: 49.99 }),
}).then(r => r.json());

// Logout
await auth.logout();
```

> **Security note:** The access token is kept in memory only (never `localStorage` or `sessionStorage`). The refresh token lives in an `httpOnly` cookie set by AuthShield, invisible to JavaScript — immune to XSS.

---

## 10. Adding a Third Service Later

When you start a new project — say, a **Reviews API** — the cost is three steps:

```bash
# 1. Copy the auth file (identical regardless of project)
cp ecommerce-api/auth.py reviews-api/auth.py
# or: cp ecommerce-api/src/auth.ts reviews-api/src/auth.ts

# 2. Add one line to reviews-api/.env
echo "JWT_SECRET_KEY=same-value-as-authshield" >> reviews-api/.env

# 3. Add user_id column to your tables (no users table)
# reviews-api/models.py  →  user_id = Column(UUID, nullable=False, index=True)
```

Same wristband. New club. Zero additional auth work.

```
AuthShield
    │
    ├── issues JWTs ──▶ E-Commerce API  (orders, products)
    ├── issues JWTs ──▶ Reviews API     (product reviews)
    └── issues JWTs ──▶ Billing API     (invoices, subscriptions)
```

All three services validate the same JWT format. All three store `user_id` as a UUID column. None of them have a users table or make runtime calls to AuthShield.

---

## 11. What You Never Build Again

| Feature | Who owns it |
|---|---|
| Registration + email verification | ✅ AuthShield |
| Login + JWT issuance | ✅ AuthShield |
| Refresh token rotation + theft detection | ✅ AuthShield |
| Forgot password / reset password | ✅ AuthShield |
| Google + GitHub OAuth | ✅ AuthShield |
| TOTP two-factor authentication | ✅ AuthShield |
| Session listing and revocation | ✅ AuthShield |
| Redis rate limiting on auth endpoints | ✅ AuthShield |
| Security headers | ✅ AuthShield |
| **Your entire auth layer** | `auth.py` / `auth.ts` — ~50 lines, never changes |

---

## JWT Payload Reference

Every protected endpoint receives this payload after validation:

```json
{
  "sub":        "550e8400-e29b-41d4-a716-446655440000",
  "email":      "shopper@example.com",
  "roles":      ["user"],
  "session_id": "abc-123-def-456",
  "jti":        "unique-token-id",
  "type":       "access",
  "iat":        1700000000,
  "exp":        1700000900
}
```

| Field | Use |
|---|---|
| `sub` | User UUID — store this as `user_id` in all your tables |
| `email` | Display name — **do not store**, it can change |
| `roles` | `["user"]`, `["user", "moderator"]`, or `["user", "admin"]` |
| `session_id` | Which login session issued this token |
| `jti` | Unique token ID — used for blacklisting on logout |
| `exp` | Unix timestamp — token invalid after this |

---

*This guide covers all officially supported integration patterns. For questions, open an issue at [github.com/ravigupta97/authshield](https://github.com/ravigupta97/authshield/issues).*
