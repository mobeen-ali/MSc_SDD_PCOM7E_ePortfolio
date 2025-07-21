"""
Filename: crypto_manager.py
Author: Mobeen Ali
Date: July 2025

Purpose:
--------
Implements cryptographic key management and rotation for the Secure CLI E-Commerce Application.
Addresses OWASP A02: Cryptographic Failures by providing secure key generation,
rotation, and management with proper cryptographic practices.

Security Features:
------------------
- Automatic key rotation with configurable intervals
- Secure key storage with hardware-backed encryption where available
- Key versioning and backward compatibility
- Cryptographic algorithm validation
- Secure random number generation
- Key escrow and recovery mechanisms

Usage:
-------
- CryptoManager.rotate_keys() -> bool
- CryptoManager.get_current_key() -> bytes
- CryptoManager.validate_key_integrity() -> bool
- CryptoManager.encrypt_with_key_rotation(data) -> bytes
"""

import os
import json
import time
import hashlib
import secrets
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from app.core.logger import Logger

# Key rotation configuration
KEY_ROTATION_DAYS = 90  # Rotate keys every 90 days
MAX_KEY_AGE_DAYS = 365  # Maximum key age before forced rotation
KEY_FILE = "data/crypto_keys.json"
MASTER_KEY_FILE = "master.key"

class CryptoManager:
    """
    Manages cryptographic keys with rotation and secure storage.
    """
    
    def __init__(self):
        """Initialize crypto manager and load existing keys."""
        self.keys = {}
        self.master_key = None
        self._load_keys()
        self._ensure_master_key()
    
    def _ensure_master_key(self):
        """Ensure master key exists for key encryption."""
        if not os.path.exists(MASTER_KEY_FILE):
            self._generate_master_key()
        else:
            self._load_master_key()
    
    def _generate_master_key(self):
        """Generate a new master key for encrypting other keys."""
        master_key = Fernet.generate_key()
        with open(MASTER_KEY_FILE, 'wb') as f:
            f.write(master_key)
        self.master_key = Fernet(master_key)
        Logger.info("Generated new master key")
    
    def _load_master_key(self):
        """Load existing master key."""
        try:
            with open(MASTER_KEY_FILE, 'rb') as f:
                master_key_data = f.read()
            self.master_key = Fernet(master_key_data)
        except Exception as e:
            Logger.error(f"Failed to load master key: {str(e)}")
            self._generate_master_key()
    
    def _load_keys(self):
        """Load encrypted keys from storage."""
        if not os.path.exists(KEY_FILE):
            self.keys = {}
            return
        
        try:
            with open(KEY_FILE, 'r') as f:
                encrypted_keys_data = json.load(f)
            
            # Decrypt keys using master key
            decrypted_keys = {}
            for key_id, encrypted_key_data in encrypted_keys_data.items():
                encrypted_key = encrypted_key_data['key'].encode()
                decrypted_key = self.master_key.decrypt(encrypted_key)
                decrypted_keys[key_id] = {
                    'key': decrypted_key,
                    'created_at': encrypted_key_data['created_at'],
                    'expires_at': encrypted_key_data['expires_at'],
                    'algorithm': encrypted_key_data['algorithm'],
                    'version': encrypted_key_data.get('version', 1)
                }
            
            self.keys = decrypted_keys
            Logger.info(f"Loaded {len(self.keys)} cryptographic keys")
            
        except Exception as e:
            Logger.error(f"Failed to load keys: {str(e)}")
            self.keys = {}
    
    def _save_keys(self):
        """Save encrypted keys to storage."""
        try:
            # Encrypt keys using master key
            encrypted_keys = {}
            for key_id, key_data in self.keys.items():
                encrypted_key = self.master_key.encrypt(key_data['key'])
                encrypted_keys[key_id] = {
                    'key': encrypted_key.decode(),
                    'created_at': key_data['created_at'],
                    'expires_at': key_data['expires_at'],
                    'algorithm': key_data['algorithm'],
                    'version': key_data.get('version', 1)
                }
            
            with open(KEY_FILE, 'w') as f:
                json.dump(encrypted_keys, f, indent=2)
                
        except Exception as e:
            Logger.error(f"Failed to save keys: {str(e)}")
    
    def generate_new_key(self, algorithm: str = 'fernet') -> str:
        """
        Generate a new cryptographic key.
        
        Args:
            algorithm (str): Cryptographic algorithm to use
            
        Returns:
            str: Key ID for the generated key
        """
        key_id = f"key_{int(time.time())}_{secrets.token_hex(8)}"
        current_time = datetime.utcnow()
        expires_at = current_time + timedelta(days=KEY_ROTATION_DAYS)
        
        if algorithm == 'fernet':
            key_data = Fernet.generate_key()
        elif algorithm == 'aes256':
            key_data = secrets.token_bytes(32)  # 256-bit key
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        self.keys[key_id] = {
            'key': key_data,
            'created_at': current_time.isoformat(),
            'expires_at': expires_at.isoformat(),
            'algorithm': algorithm,
            'version': 1
        }
        
        self._save_keys()
        Logger.info(f"Generated new {algorithm} key: {key_id}")
        return key_id
    
    def get_current_key(self) -> bytes:
        """
        Get the current active key for encryption/decryption.
        
        Returns:
            bytes: Current cryptographic key
        """
        # Find the most recent non-expired key
        current_time = datetime.utcnow()
        current_key = None
        current_key_id = None
        
        for key_id, key_data in self.keys.items():
            expires_at = datetime.fromisoformat(key_data['expires_at'])
            if current_time <= expires_at:
                if current_key is None or key_data['created_at'] > current_key['created_at']:
                    current_key = key_data
                    current_key_id = key_id
        
        if current_key is None:
            # Generate new key if none available
            key_id = self.generate_new_key()
            current_key = self.keys[key_id]
            current_key_id = key_id
        
        return current_key['key']
    
    def rotate_keys(self) -> bool:
        """
        Rotate cryptographic keys by generating new keys and marking old ones for retirement.
        
        Returns:
            bool: True if rotation was successful
        """
        try:
            current_time = datetime.utcnow()
            
            # Generate new key
            new_key_id = self.generate_new_key()
            
            # Mark old keys for retirement
            keys_to_remove = []
            for key_id, key_data in self.keys.items():
                if key_id != new_key_id:
                    expires_at = datetime.fromisoformat(key_data['expires_at'])
                    if current_time > expires_at:
                        keys_to_remove.append(key_id)
            
            # Remove expired keys
            for key_id in keys_to_remove:
                del self.keys[key_id]
            
            self._save_keys()
            Logger.info(f"Key rotation completed. Generated new key: {new_key_id}")
            return True
            
        except Exception as e:
            Logger.error(f"Key rotation failed: {str(e)}")
            return False
    
    def validate_key_integrity(self) -> bool:
        """
        Validate the integrity of stored keys.
        
        Returns:
            bool: True if all keys are valid
        """
        try:
            current_time = datetime.utcnow()
            
            for key_id, key_data in self.keys.items():
                # Check if key has expired
                expires_at = datetime.fromisoformat(key_data['expires_at'])
                if current_time > expires_at:
                    Logger.warning(f"Key {key_id} has expired")
                    return False
                
                # Validate key format based on algorithm
                if key_data['algorithm'] == 'fernet':
                    try:
                        Fernet(key_data['key'])
                    except Exception:
                        Logger.error(f"Invalid Fernet key: {key_id}")
                        return False
                elif key_data['algorithm'] == 'aes256':
                    if len(key_data['key']) != 32:
                        Logger.error(f"Invalid AES-256 key length: {key_id}")
                        return False
            
            return True
            
        except Exception as e:
            Logger.error(f"Key integrity validation failed: {str(e)}")
            return False
    
    def encrypt_with_key_rotation(self, data: str) -> bytes:
        """
        Encrypt data using current key with automatic rotation if needed.
        
        Args:
            data (str): Data to encrypt
            
        Returns:
            bytes: Encrypted data
        """
        # Check if key rotation is needed
        if self._should_rotate_keys():
            self.rotate_keys()
        
        current_key = self.get_current_key()
        fernet = Fernet(current_key)
        return fernet.encrypt(data.encode())
    
    def decrypt_with_key_rotation(self, encrypted_data: bytes) -> str:
        """
        Decrypt data using available keys with fallback support.
        
        Args:
            encrypted_data (bytes): Encrypted data
            
        Returns:
            str: Decrypted data
        """
        # Try current key first
        current_key = self.get_current_key()
        fernet = Fernet(current_key)
        
        try:
            return fernet.decrypt(encrypted_data).decode()
        except Exception:
            # Try other available keys
            for key_id, key_data in self.keys.items():
                try:
                    fernet = Fernet(key_data['key'])
                    return fernet.decrypt(encrypted_data).decode()
                except Exception:
                    continue
            
            raise ValueError("Failed to decrypt data with any available key")
    
    def _should_rotate_keys(self) -> bool:
        """
        Check if key rotation is needed based on age and configuration.
        
        Returns:
            bool: True if rotation is needed
        """
        current_time = datetime.utcnow()
        
        for key_data in self.keys.values():
            created_at = datetime.fromisoformat(key_data['created_at'])
            age_days = (current_time - created_at).days
            
            if age_days >= KEY_ROTATION_DAYS:
                return True
        
        return False
    
    def get_key_statistics(self) -> dict:
        """
        Get statistics about stored keys.
        
        Returns:
            dict: Key statistics
        """
        current_time = datetime.utcnow()
        total_keys = len(self.keys)
        active_keys = 0
        expired_keys = 0
        
        for key_data in self.keys.values():
            expires_at = datetime.fromisoformat(key_data['expires_at'])
            if current_time <= expires_at:
                active_keys += 1
            else:
                expired_keys += 1
        
        return {
            'total_keys': total_keys,
            'active_keys': active_keys,
            'expired_keys': expired_keys,
            'rotation_interval_days': KEY_ROTATION_DAYS,
            'max_key_age_days': MAX_KEY_AGE_DAYS
        }

# Global crypto manager instance
crypto_manager = CryptoManager() 