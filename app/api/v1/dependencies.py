"""
app/api/v1/dependencies.py

FastAPI dependencies shared across multiple endpoints.
We'll add more (get_current_user, require_roles) in later steps.
"""

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db  # re-export for convenience

# Re-export get_db so endpoints can import from one place
__all__ = ["get_db"]