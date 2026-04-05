"""Shared test fixtures for arm-auth."""

import pytest
from sqlalchemy.pool import StaticPool

from arm_auth.db import AuthDB


@pytest.fixture
def auth_db(tmp_path):
    """Create an in-memory auth database for testing."""
    db = AuthDB()
    db.init_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    db.create_all()
    yield db
    db.dispose()
