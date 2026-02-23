"""

Seeds the database with required initial data.
Run once after migrations. Safe to run multiple times (idempotent).

WHY SEED ROLES?
The three roles (user, admin, moderator) are the foundation of RBAC.
They must exist before any user can register. We can't create them
via the API because the API requires auth — chicken and egg problem.
"""

import asyncio

from sqlalchemy import select

from app.db.session import AsyncSessionLocal
from app.models.role import Role


DEFAULT_ROLES = [
    {
        "name": "user",
        "description": "Standard user with basic access rights.",
    },
    {
        "name": "moderator",
        "description": "Can moderate content and manage standard users.",
    },
    {
        "name": "admin",
        "description": "Full administrative access to all resources.",
    },
]


async def seed_roles() -> None:
    """
    Creates the default roles if they don't already exist.
    Safe to call multiple times — skips roles that already exist.
    """
    async with AsyncSessionLocal() as session:
        for role_data in DEFAULT_ROLES:
            # Check if role already exists
            result = await session.execute(
                select(Role).where(Role.name == role_data["name"])
            )
            existing = result.scalar_one_or_none()

            if not existing:
                role = Role(**role_data)
                session.add(role)
                print(f"  Created role: {role_data['name']}")
            else:
                print(f"  Role already exists: {role_data['name']}")

        await session.commit()
        print("Role seeding complete.")


async def run_seeds() -> None:
    print("Running database seeds...")
    await seed_roles()
    print("All seeds complete.")


if __name__ == "__main__":
    asyncio.run(run_seeds())