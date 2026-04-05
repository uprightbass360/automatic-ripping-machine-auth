"""Auth service — CRUD operations for users and groups."""

import json
import logging
from typing import Optional

from sqlalchemy.orm import make_transient

from arm_auth.db import AuthDB
from arm_auth.models import User, Group
from arm_auth.passwords import hash_password, verify_password
from arm_auth.scopes import DEFAULT_GROUPS

logger = logging.getLogger(__name__)


class AuthService:
    """High-level operations for managing auth users and groups."""

    def __init__(self, db: AuthDB):
        self.db = db

    def seed_defaults(self):
        """Create default groups if they don't exist."""
        with self.db.session() as s:
            for name, definition in DEFAULT_GROUPS.items():
                existing = s.query(Group).filter_by(name=name).first()
                if existing is None:
                    group = Group(name=name, scopes=json.dumps(definition["scopes"]))
                    s.add(group)
                    logger.info("Seeded default group: %s", name)

    def create_user(
        self,
        username: str,
        password: str,
        email: Optional[str] = None,
        group_name: str = "user",
    ) -> User:
        """Create a new user with a hashed password and group assignment."""
        with self.db.session() as s:
            existing = s.query(User).filter_by(username=username).first()
            if existing is not None:
                raise ValueError(f"User '{username}' already exists")

            group = s.query(Group).filter_by(name=group_name).first()
            if group is None:
                raise ValueError(f"Group '{group_name}' does not exist")

            user = User(
                username=username,
                email=email,
                password_hash=hash_password(password),
            )
            user.groups.append(group)
            s.add(user)
            s.flush()
            # Force-load all attributes and relationships before session closes
            s.refresh(user)
            _ = [(g.id, g.name, g.scopes) for g in user.groups]
            s.expunge(user)
            for g in user.groups:
                s.expunge(g)
            make_transient(user)
            return user

    def list_users(self) -> list[User]:
        """Return all users with their groups loaded."""
        with self.db.session() as s:
            users = s.query(User).all()
            for u in users:
                _ = [(g.id, g.name, g.scopes) for g in u.groups]
                s.expunge(u)
                for g in u.groups:
                    s.expunge(g)
                make_transient(u)
            return users

    def get_user(self, username: str) -> Optional[User]:
        """Look up a user by username."""
        with self.db.session() as s:
            user = s.query(User).filter_by(username=username).first()
            if user is not None:
                _ = [(g.id, g.name, g.scopes) for g in user.groups]
                s.expunge(user)
                for g in user.groups:
                    s.expunge(g)
                make_transient(user)
            return user

    def update_user(
        self,
        user_id: int,
        email: Optional[str] = None,
        group_name: Optional[str] = None,
        active: Optional[bool] = None,
    ) -> User:
        """Update a user's email, group, or active status."""
        with self.db.session() as s:
            user = s.get(User, user_id)
            if user is None:
                raise ValueError(f"User ID {user_id} not found")
            if email is not None:
                user.email = email
            if active is not None:
                user.active = active
            if group_name is not None:
                group = s.query(Group).filter_by(name=group_name).first()
                if group is None:
                    raise ValueError(f"Group '{group_name}' does not exist")
                user.groups.clear()
                user.groups.append(group)
            s.flush()
            s.refresh(user)
            _ = [(g.id, g.name, g.scopes) for g in user.groups]
            s.expunge(user)
            for g in user.groups:
                s.expunge(g)
            make_transient(user)
            return user

    def update_password(self, user_id: int, new_password: str):
        """Change a user's password."""
        with self.db.session() as s:
            user = s.get(User, user_id)
            if user is None:
                raise ValueError(f"User ID {user_id} not found")
            user.password_hash = hash_password(new_password)

    def delete_user(self, user_id: int):
        """Delete a user. Prevents deleting the last admin."""
        with self.db.session() as s:
            user = s.get(User, user_id)
            if user is None:
                raise ValueError(f"User ID {user_id} not found")

            if any(g.name == "admin" for g in user.groups):
                admin_group = s.query(Group).filter_by(name="admin").first()
                if admin_group and len(admin_group.users) <= 1:
                    raise ValueError("Cannot delete the last admin user")

            s.delete(user)

    def verify_credentials(self, username: str, password: str) -> Optional[User]:
        """Verify username + password. Returns user if valid, None otherwise."""
        with self.db.session() as s:
            user = s.query(User).filter_by(username=username, active=True).first()
            if user is None:
                return None
            if not verify_password(password, user.password_hash):
                return None
            _ = [(g.id, g.name, g.scopes) for g in user.groups]
            s.expunge(user)
            for g in user.groups:
                s.expunge(g)
            make_transient(user)
            return user
