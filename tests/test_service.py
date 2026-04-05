"""Tests for auth service CRUD operations."""

import pytest

from arm_auth.service import AuthService
from arm_auth.models import User, Group
from arm_auth.scopes import DEFAULT_GROUPS


class TestAuthServiceInit:
    def test_seed_default_groups(self, auth_db):
        svc = AuthService(auth_db)
        svc.seed_defaults()

        with auth_db.session() as s:
            groups = s.query(Group).all()
            names = {g.name for g in groups}
            assert "admin" in names
            assert "user" in names

    def test_seed_defaults_idempotent(self, auth_db):
        svc = AuthService(auth_db)
        svc.seed_defaults()
        svc.seed_defaults()

        with auth_db.session() as s:
            count = s.query(Group).count()
            assert count == len(DEFAULT_GROUPS)


class TestUserCRUD:
    @pytest.fixture(autouse=True)
    def setup(self, auth_db):
        self.db = auth_db
        self.svc = AuthService(auth_db)
        self.svc.seed_defaults()

    def test_create_user(self):
        user = self.svc.create_user("admin", "secret", "admin@arm.local", "admin")
        assert user.id is not None
        assert user.username == "admin"
        assert user.email == "admin@arm.local"
        assert user.password_hash.startswith("$2b$")
        assert len(user.groups) == 1
        assert user.groups[0].name == "admin"

    def test_create_user_default_group(self):
        user = self.svc.create_user("viewer", "secret")
        assert len(user.groups) == 1
        assert user.groups[0].name == "user"

    def test_create_duplicate_username_raises(self):
        self.svc.create_user("admin", "secret")
        with pytest.raises(ValueError, match="already exists"):
            self.svc.create_user("admin", "other")

    def test_list_users(self):
        self.svc.create_user("alice", "pw1")
        self.svc.create_user("bob", "pw2")
        users = self.svc.list_users()
        assert len(users) == 2
        names = {u.username for u in users}
        assert names == {"alice", "bob"}

    def test_get_user_by_username(self):
        self.svc.create_user("admin", "secret")
        user = self.svc.get_user("admin")
        assert user is not None
        assert user.username == "admin"

    def test_get_user_not_found(self):
        assert self.svc.get_user("ghost") is None

    def test_update_user(self):
        user = self.svc.create_user("admin", "secret")
        updated = self.svc.update_user(user.id, email="new@arm.local", group_name="user")
        assert updated.email == "new@arm.local"
        assert updated.groups[0].name == "user"

    def test_update_password(self):
        user = self.svc.create_user("admin", "old")
        self.svc.update_password(user.id, "new")
        from arm_auth.passwords import verify_password
        with self.db.session() as s:
            refreshed = s.get(User, user.id)
            assert verify_password("new", refreshed.password_hash)
            assert not verify_password("old", refreshed.password_hash)

    def test_delete_user(self):
        user = self.svc.create_user("temp", "pw")
        self.svc.delete_user(user.id)
        assert self.svc.get_user("temp") is None

    def test_delete_last_admin_raises(self):
        user = self.svc.create_user("admin", "pw", group_name="admin")
        with pytest.raises(ValueError, match="last admin"):
            self.svc.delete_user(user.id)

    def test_verify_credentials(self):
        self.svc.create_user("admin", "secret")
        user = self.svc.verify_credentials("admin", "secret")
        assert user is not None
        assert user.username == "admin"

    def test_verify_credentials_wrong_password(self):
        self.svc.create_user("admin", "secret")
        assert self.svc.verify_credentials("admin", "wrong") is None

    def test_verify_credentials_unknown_user(self):
        assert self.svc.verify_credentials("ghost", "pw") is None

    def test_verify_credentials_inactive_user(self):
        user = self.svc.create_user("admin", "secret")
        self.svc.update_user(user.id, active=False)
        assert self.svc.verify_credentials("admin", "secret") is None
