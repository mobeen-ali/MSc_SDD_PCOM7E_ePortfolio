import pytest
from oop_auth_example import User, AdminUser


def test_user_password_check_success():
    user = User("mobeen", "MyPass123")
    assert user.check_password("MyPass123") is True


def test_user_password_check_failure():
    user = User("mobeen", "MyPass123")
    assert user.check_password("WrongPass") is False


def test_admin_user_inherits_user():
    admin = AdminUser("admin", "SecureAdmin123", access_level=10)
    assert isinstance(admin, User)
    assert admin.access_level == 10
    assert admin.check_password("SecureAdmin123") is True


def test_password_is_hashed():
    user = User("testuser", "Secret123")
    # Accessing the hashed password directly (not recommended normally)
    hashed = user._password_hash
    assert isinstance(hashed, bytes)
    assert b"Secret123" not in hashed  # Ensure plaintext is not in the hash
