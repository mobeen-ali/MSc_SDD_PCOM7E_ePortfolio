"""
Filename: test_user.py
Author: Mobeen Ali
Date: July 2025

Purpose:
--------
Unit tests for the User model in the Secure CLI E-Commerce Application.

Tests include:
- Password hashing and verification
- OTP generation and TOTP verification (2FA)

Security Context:
-----------------
- Passwords are hashed using bcrypt with auto-generated salt
- OTPs use time-based one-time password (TOTP) via PyOTP
"""


import pytest
from app.models.user import User
import bcrypt
import pyotp


def test_password_verification():
    """
    Verify that:
    - The correct password passes the bcrypt check
    - An incorrect password fails
    """
    password = "SecurePass123!@#"
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    user = User("testuser", hashed)

    assert user.verify_password(password) is True
    assert user.verify_password("wrongpass") is False


def test_otp_generation_and_verification():
    """
    Verify that:
    - A freshly generated OTP passes the TOTP check
    - A fake/inaccurate OTP fails the check
    """
    user = User("otpuser", "fakehash") # Password hash not needed here
    otp = user.get_otp_token()

    assert user.verify_otp(otp) is True
    assert user.verify_otp("123456") is False
