import pytest
from oop_auth_example import User, AdminUser


def test_user_password_check_success():
    """
    Test that a user can successfully authenticate with the correct password.
    """
    print("\n[Test] Checking correct password authentication for regular user...")
    user = User("mobeen", "MyPass123")
    assert user.check_password("MyPass123") is True
    print("[Pass] Correct password successfully validated.")


def test_user_password_check_failure():
    """
    Test that authentication fails with an incorrect password.
    """
    print("\n[Test] Checking incorrect password rejection for regular user...")
    user = User("mobeen", "MyPass123")
    assert user.check_password("WrongPass") is False
    print("[Pass] Incorrect password correctly rejected.")


def test_admin_user_inherits_user():
    """
    Test that AdminUser correctly inherits from User and retains full functionality.
    """
    print("\n[Test] Verifying AdminUser inheritance and functionality...")
    admin = AdminUser("admin", "SecureAdmin123", access_level=10)
    assert isinstance(admin, User)
    assert admin.access_level == 10
    assert admin.check_password("SecureAdmin123") is True
    print("[Pass] AdminUser successfully inherits and functions like User.")


def test_password_is_hashed():
    """
    Test that the user's password is stored in hashed form and not as plaintext.
    """
    print("\n[Test] Verifying password is hashed and plaintext is not stored...")
    user = User("testuser", "Secret123")
    hashed = user._password_hash  # Normally should not access a protected attribute directly
    assert isinstance(hashed, bytes)
    assert b"Secret123" not in hashed
    print("[Pass] Password stored securely as a hash and not as plaintext.")
