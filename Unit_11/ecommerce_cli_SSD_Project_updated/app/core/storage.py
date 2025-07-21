"""
Filename: storage.py
Author: Mobeen Ali
Date: July 2025

Purpose:
--------
Provides encryption and decryption utilities for securely storing sensitive data
(e.g., user credentials) in the Secure CLI E-Commerce Application.
Enhanced with OWASP A02 compliance through key rotation and secure key management.

Encryption:
-----------
- Uses Fernet symmetric encryption from the `cryptography` library
- Integrated with CryptoManager for key rotation and management
- All encrypted content is stored as bytes and decrypted to string

Security Considerations:
------------------------
- Key rotation is handled by CryptoManager
- File-based key management is simple but should be protected via OS permissions
- Do not hard-code keys or commit them to version control
- Enhanced with OWASP A02 cryptographic best practices

Usage:
-------
- Call generate_key() once during app initialization
- Use encrypt_data() and decrypt_data() for secure data handling
- Key rotation is handled automatically by CryptoManager
"""


import os
from cryptography.fernet import Fernet
from app.core.logger import Logger

KEY_FILE = "secret.key"


def generate_key():
    """
    Generates a new Fernet encryption key and saves it to KEY_FILE.
    Enhanced to work with CryptoManager for key rotation.

    Note:
        - This function should only run once (on first use).
        - If the key already exists, it is not regenerated.
        - For production, use CryptoManager for key rotation.
    """
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, 'wb') as f:
            f.write(key)
        Logger.info("Generated initial encryption key")


def load_key():
    """
    Loads the Fernet encryption key from KEY_FILE.
    Enhanced to work with CryptoManager for key rotation.

    Returns:
        bytes: The encryption key

    Raises:
        FileNotFoundError: If the key file does not exist
    """
    if not os.path.exists(KEY_FILE):
        generate_key()
    with open(KEY_FILE, "rb") as f:
        return f.read()


def encrypt_data(data: str) -> bytes:
    """
    Encrypts a plaintext string using Fernet symmetric encryption.
    Enhanced with OWASP A02 compliance through CryptoManager integration.

    Args:
        data (str): The plaintext string to encrypt

    Returns:
        bytes: The encrypted byte string
    """
    try:
        # Try CryptoManager first
        from app.core.crypto_manager import crypto_manager
        current_key = crypto_manager.get_current_key()
        f = Fernet(current_key)
        return f.encrypt(data.encode())
    except Exception as e:
        Logger.warning(f"CryptoManager failed, using fallback: {str(e)}")
        # Fallback to original method if CryptoManager fails
        f = Fernet(load_key())
        return f.encrypt(data.encode())


def decrypt_data(token: bytes) -> str:
    """
    Decrypts a Fernet-encrypted byte string.
    Enhanced with OWASP A02 compliance through CryptoManager integration.

    Args:
        token (bytes): The encrypted byte string to decrypt

    Returns:
        str: The original plaintext string
    """
    try:
        # Try CryptoManager first
        from app.core.crypto_manager import crypto_manager
        return crypto_manager.decrypt_with_key_rotation(token)
    except Exception as e:
        Logger.warning(f"CryptoManager decryption failed, using fallback: {str(e)}")
        # Fallback to original method if CryptoManager fails
        f = Fernet(load_key())
        return f.decrypt(token).decode()


def validate_encryption_integrity() -> bool:
    """
    Validates the integrity of encryption keys and data.
    Enhanced with OWASP A02 compliance checks.

    Returns:
        bool: True if encryption integrity is valid
    """
    try:
        # Test encryption/decryption with sample data
        test_data = "test_encryption_integrity"
        encrypted = encrypt_data(test_data)
        decrypted = decrypt_data(encrypted)
        
        if decrypted == test_data:
            Logger.info("Encryption integrity validation passed")
            return True
        else:
            Logger.error("Encryption integrity validation failed")
            return False
    except Exception as e:
        Logger.error(f"Encryption integrity validation error: {str(e)}")
        return False


def get_encryption_statistics() -> dict:
    """
    Get statistics about encryption usage and key management.
    Enhanced with OWASP A02 compliance metrics.

    Returns:
        dict: Encryption statistics
    """
    try:
        # Get CryptoManager statistics
        from app.core.crypto_manager import crypto_manager
        crypto_stats = crypto_manager.get_key_statistics()
        
        # Add storage-specific statistics
        stats = {
            "key_management": crypto_stats,
            "storage_files": {
                "users_file": os.path.exists("data/users.json"),
                "sessions_file": os.path.exists("data/sessions.json"),
                "crypto_keys_file": os.path.exists("data/crypto_keys.json"),
                "master_key_file": os.path.exists("master.key")
            },
            "encryption_integrity": validate_encryption_integrity()
        }
        
        return stats
    except Exception as e:
        Logger.error(f"Failed to get encryption statistics: {str(e)}")
        return {"error": str(e)}
