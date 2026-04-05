"""FastAPI auth dependencies.

Two modes:
- Enabled (behind Traefik + Tinyauth): reads Remote-User header, resolves scopes from auth DB
- Disabled (default): returns synthetic admin user, all endpoints open
"""

import logging
from dataclasses import dataclass, field
from typing import Optional

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import make_transient

from arm_auth.db import AuthDB
from arm_auth.models import User

logger = logging.getLogger(__name__)


@dataclass
class SyntheticUser:
    """Fake user returned when auth is disabled."""
    id: int = 0
    username: str = "anonymous"
    email: Optional[str] = None
    active: bool = True
    groups: list = field(default_factory=list)

    @property
    def all_scopes(self) -> set[str]:
        return {"*"}

    def has_scope(self, scope: str) -> bool:
        return True


class AuthDependencies:
    """Container for FastAPI auth dependencies."""

    def __init__(self, db: AuthDB, enabled: bool = False):
        self._db = db
        self._enabled = enabled

    @property
    def get_current_user(self):
        """FastAPI Depends() for getting the authenticated user."""
        db = self._db
        enabled = self._enabled

        async def _get_current_user(request: Request):
            if not enabled:
                return SyntheticUser()

            remote_user = request.headers.get("Remote-User")
            if not remote_user:
                raise HTTPException(status_code=401, detail="Not authenticated")

            with db.session() as s:
                user = s.query(User).filter_by(username=remote_user, active=True).first()
                if user is None:
                    raise HTTPException(status_code=401, detail="User not found or inactive")
                _ = [(g.name, g.scopes) for g in user.groups]
                s.expunge(user)
                for g in user.groups:
                    s.expunge(g)
                make_transient(user)
                return user

        return Depends(_get_current_user)

    def require_scope(self, scope: str):
        """FastAPI Depends() that requires a specific scope."""
        db = self._db
        enabled = self._enabled

        async def _require_scope(request: Request):
            if not enabled:
                return SyntheticUser()

            remote_user = request.headers.get("Remote-User")
            if not remote_user:
                raise HTTPException(status_code=401, detail="Not authenticated")

            with db.session() as s:
                user = s.query(User).filter_by(username=remote_user, active=True).first()
                if user is None:
                    raise HTTPException(status_code=401, detail="User not found or inactive")
                _ = [(g.name, g.scopes) for g in user.groups]
                has_scope = user.has_scope(scope)
                s.expunge(user)
                for g in user.groups:
                    s.expunge(g)
                make_transient(user)
                if not has_scope:
                    raise HTTPException(status_code=403, detail=f"Insufficient permissions: requires '{scope}'")
                return user

        return Depends(_require_scope)


def create_auth_dependencies(db: AuthDB, enabled: bool = False) -> AuthDependencies:
    """Factory for creating auth dependencies."""
    return AuthDependencies(db=db, enabled=enabled)
