"""
Filename: test_auth.py
Author: Mobeen Ali
Date: July 2025

Purpose:
--------
Unit tests for the authentication module in the Secure CLI E-Commerce Application.
Uses pytest to validate:
- User registration
- OTP-based login
- Handling of invalid login attempts
"""


import os
import pytest
from app.core import auth
from app.models.user import User

# Test DB file used to isolate test runs
TEST_DB = "test_users.json"

@pytest.fixture(autouse=True)
def clean_user_db(monkeypatch):
    """
    Pytest fixture to ensure test isolation.

    - Overrides the USERS_DB path in the auth module to use a test file
    - Deletes the file before and after each test to ensure a clean environment
    """
    monkeypatch.setattr(auth, "USERS_DB", TEST_DB)
    # Remove test file before and after each test
    if os.path.exists(TEST_DB):
        os.remove(TEST_DB)
    yield
    if os.path.exists(TEST_DB):
        os.remove(TEST_DB)


def test_register_and_login_user(monkeypatch):
    """
    Test full user registration and OTP-based login workflow.
    Includes:
    - Successful registration
    - Preventing duplicate users
    - Login with correct password and OTP
    - Rejection of wrong password or wrong OTP
    """
    username = "testuser"
    password = "TestPassword!@#123"

    # First registration should succeed
    assert auth.register_user(username, password) is True

    # Duplicate registration should fail
    assert auth.register_user(username, password) is False

    # Load registered user and simulate OTP generation
    users = auth._load_users()
    user_data = users[username]
    test_user = User.from_dict(user_data)
    otp = test_user.get_otp_token()

    # Should authenticate with correct credentials and OTP
    assert auth.authenticate_user(username, password, otp) is True

    # Should reject invalid password
    assert auth.authenticate_user(username, "wrongpassword", otp) is False

    # Should reject invalid OTP
    assert auth.authenticate_user(username, password, "123456") is False
