"""
Filename: user.py
Author: Mobeen Ali
Date: July 2025

Purpose:
--------
Defines the User model for the Secure CLI E-Commerce Application.

Security Features:
------------------
- Passwords are stored as bcrypt hashes (with automatic salt)
- Two-Factor Authentication (2FA) via TOTP using pyotp
- Role-based access control (default role: "user")
- User secrets are stored and reused for consistent OTP validation

Usage:
-------
user = User("alice", "<hashed_pw>")
user.verify_password("plaintext_pw") -> True/False
user.get_otp_token() -> str
user.verify_otp("123456") -> True/False
"""


import pyotp
import bcrypt


class User:
    """
    Represents a registered user with password hashing and 2FA support.
    """
    def __init__(self, username: str, hashed_password: str, role: str = "user", secret: str = None):
        """
        Initializes a new User instance.

        Args:
            username (str): The user's login name
            hashed_password (str): Bcrypt-hashed password
            role (str, optional): Role of the user (e.g., "user", "admin"). Defaults to "user".
            secret (str, optional): Base32-encoded OTP secret. If not provided, a new one is generated.
        """
        self.username = username
        self.hashed_password = hashed_password
        self.role = role
        self.secret = secret or pyotp.random_base32()

    def verify_password(self, password: str) -> bool:
        """
        Verifies a plaintext password against the stored bcrypt hash.

        Args:
            password (str): Plaintext password entered by the user

        Returns:
            bool: True if the password is correct, False otherwise
        """
        return bcrypt.checkpw(password.encode(), self.hashed_password.encode())

    def get_otp_token(self):
        """
        Generates the current time-based OTP token.

        Returns:
            str: A 6-digit TOTP token
        """
        totp = pyotp.TOTP(self.secret)
        return totp.now()

    def verify_otp(self, otp_code: str) -> bool:
        """
        Verifies a given OTP code against the user's TOTP secret.

        Args:
            otp_code (str): The 6-digit token entered by the user

        Returns:
            bool: True if the token is valid, False otherwise
        """
        totp = pyotp.TOTP(self.secret)
        return totp.verify(otp_code)

    def to_dict(self):
        """
        Serializes the User instance to a dictionary for storage.

        Returns:
            dict: User data
        """
        return {
            "username": self.username,
            "hashed_password": self.hashed_password,
            "role": self.role,
            "secret": self.secret
        }

    @staticmethod
    def from_dict(data: dict):
        """
        Deserializes a dictionary into a User instance.

        Args:
            data (dict): Dictionary containing user fields

        Returns:
            User: A new User object populated from dictionary
        """
        return User(
            username=data["username"],
            hashed_password=data["hashed_password"],
            role=data.get("role", "user"),
            secret=data.get("secret")
        )
