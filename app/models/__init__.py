"""
app/models/__init__.py

Import all models here so SQLAlchemy's metadata knows about them.
Alembic reads Base.metadata to detect schema changes — if a model
isn't imported, Alembic won't see it and won't generate migrations for it.
"""

from app.models.login_history import LoginHistory
from app.models.refresh_token import RefreshToken
from app.models.role import Role, user_roles
from app.models.session import Session
from app.models.user import User

__all__ = [
    "User",
    "Role",
    "user_roles",
    "RefreshToken",
    "Session",
    "LoginHistory",
]