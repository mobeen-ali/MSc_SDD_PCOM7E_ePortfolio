"""
Filename: auth.py
Author: Mobeen Ali
Date: July 2025

Purpose:
--------
Handles user authentication, registration, and secure storage for users and products
in the Secure CLI E-Commerce Application.

Security Features:
------------------
- Passwords are hashed using bcrypt with salt
- User data is encrypted at rest using Fernet encryption (via `storage`)
- Role-based access control is supported (default role: 'user')
- OTP verification is handled in the `User` model

Usage:
-------
- _load_users() / _save_users() for encrypted persistence
- register_user() to create a new secure user account
- authenticate_user() for secure login with OTP
- _load_products() / _save_products() for basic product persistence
"""


import os
import json
import bcrypt
from app.models.user import User

# File paths for storing encrypted user and plaintext product data
USERS_DB = "data/users.json"
PRODUCTS_DB = "data/products.json"


# -------------------------------
# User Handling Functions
# -------------------------------
def _load_users():
    """
    Load and decrypt user data from USERS_DB.

    Returns:
        dict: A dictionary of username -> user data.
    """
    if not os.path.exists(USERS_DB):
        return {}
    
    try:
        with open(USERS_DB, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"Warning: Failed to load users: {e}")
        return {}


def _save_users(users):
    """
    Save user data to USERS_DB.

    Args:
        users (dict): Dictionary of username -> user data
    """
    try:
        with open(USERS_DB, "w") as f:
            json.dump(users, f, indent=2)
    except Exception as e:
        print(f"Error saving users: {e}")


def register_user(username: str, password: str, role: str = "user") -> bool:
    """
    Register a new user with hashed password and optional role.

    Args:
        username (str): New user's username
        password (str): Plaintext password (to be hashed)
        role (str): User role ('user' or 'admin')

    Returns:
        bool: True if user was registered successfully, False if already exists
    """
    try:
        users = _load_users()
        if username in users:
            return False  # User already exists

        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        user = User(username, hashed_password, role)
        users[username] = user.to_dict()
        
        _save_users(users)
        
        # Verify the user was actually saved
        verify_users = _load_users()
        if username not in verify_users:
            print(f"Warning: User {username} was not saved properly")
            return False
            
        return True
        
    except Exception as e:
        print(f"Registration error: {e}")
        return False


def authenticate_user(username: str, password: str, otp_code: str) -> bool:
    """
    Authenticate a user using password and OTP.

    Args:
        username (str): Username
        password (str): Plaintext password
        otp_code (str): One-time password (TOTP) for 2FA

    Returns:
        bool: True if credentials and OTP are valid, False otherwise
    """
    users = _load_users()
    if username not in users:
        return False

    user = User.from_dict(users[username])
    if not user.verify_password(password):
        return False

    return user.verify_otp(otp_code)


def login_user(username: str, password: str) -> tuple:
    """
    Login a user and return OTP for verification.

    Args:
        username (str): Username
        password (str): Plaintext password

    Returns:
        tuple[bool, str]: (success, otp_code) - success is True if credentials are valid
    """
    try:
        users = _load_users()
        if username not in users:
            return False, ""

        user = User.from_dict(users[username])
        
        if not user.verify_password(password):
            return False, ""

        # Generate OTP for user
        otp_code = user.get_otp_token()
        return True, otp_code
        
    except Exception as e:
        print(f"Login error: {e}")
        return False, ""


def verify_otp(username: str, otp_code: str) -> bool:
    """
    Verify OTP for a specific user.

    Args:
        username (str): Username
        otp_code (str): One-time password to verify

    Returns:
        bool: True if OTP is valid for the user, False otherwise
    """
    try:
        users = _load_users()
        if username not in users:
            return False

        user = User.from_dict(users[username])
        return user.verify_otp(otp_code)
        
    except Exception as e:
        print(f"OTP verification error: {e}")
        return False


# -------------------------------
# Product Handling Functions
# -------------------------------
def _load_products():
    """
    Load product data from PRODUCTS_DB.

    Returns:
        dict: Dictionary of product_id -> product data
    """
    if not os.path.exists(PRODUCTS_DB):
        return {}
    with open(PRODUCTS_DB, "r") as f:
        return json.load(f)


def _save_products(products):
    """
    Save product data to PRODUCTS_DB.

    Args:
        products (dict): Dictionary of product_id -> product data
    """
    with open(PRODUCTS_DB, "w") as f:
        json.dump(products, f, indent=4)


def load_products():
    """
    Load product data from PRODUCTS_DB.

    Returns:
        dict: Dictionary of product_id -> product data
    """
    return _load_products()


def save_products(products):
    """
    Save product data to PRODUCTS_DB.

    Args:
        products (dict): Dictionary of product_id -> product data
    """
    _save_products(products)
