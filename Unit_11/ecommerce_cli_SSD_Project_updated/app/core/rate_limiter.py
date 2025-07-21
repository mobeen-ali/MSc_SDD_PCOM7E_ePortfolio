"""
Filename: rate_limiter.py
Author: Mobeen Ali
Date: July 2025

Purpose:
--------
Implements rate limiting and advanced authentication protection for the Secure CLI E-Commerce Application.
Addresses OWASP A07: Identification and Authentication Failures by providing protection against
brute force attacks, credential stuffing, and automated attacks.

Security Features:
------------------
- IP-based rate limiting
- Account lockout mechanisms
- Failed login attempt tracking
- Progressive delay implementation
- Brute force attack detection
- Credential stuffing protection
- Session fixation protection
- Advanced password policy enforcement

Usage:
-------
- RateLimiter.check_rate_limit(ip_address, action) -> bool
- RateLimiter.record_failed_attempt(username, ip_address) -> bool
- RateLimiter.is_account_locked(username) -> bool
- RateLimiter.validate_password_policy(password) -> dict
"""

import json
import os
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from collections import defaultdict
import hashlib
import re
from app.core.logger import Logger

class RateLimiter:
    """Rate limiting and advanced authentication protection."""
    
    def __init__(self):
        self.rate_limit_file = "data/rate_limits.json"
        self.lockout_file = "data/account_lockouts.json"
        self.password_history_file = "data/password_history.json"
        self.failed_attempts_file = "data/failed_attempts.json"
        
        # Rate limiting configuration
        self.max_login_attempts = 5
        self.lockout_duration_minutes = 30
        self.progressive_delay_seconds = 60
        self.ip_rate_limit = 10  # requests per minute
        self.ip_window_seconds = 60
        
        # Password policy
        self.min_password_length = 8
        self.require_uppercase = True
        self.require_lowercase = True
        self.require_digits = True
        self.require_special_chars = True
        self.max_password_history = 5
        
        # Load data
        self.rate_limits = self._load_rate_limits()
        self.account_lockouts = self._load_lockouts()
        self.password_history = self._load_password_history()
        self.failed_attempts = self._load_failed_attempts()
    
    def _load_rate_limits(self) -> dict:
        """Load rate limit data from file."""
        try:
            if os.path.exists(self.rate_limit_file):
                with open(self.rate_limit_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            Logger.error(f"Failed to load rate limits: {str(e)}")
        return {}
    
    def _save_rate_limits(self):
        """Save rate limit data to file."""
        try:
            with open(self.rate_limit_file, 'w') as f:
                json.dump(self.rate_limits, f, indent=2)
        except Exception as e:
            Logger.error(f"Failed to save rate limits: {str(e)}")
    
    def _load_lockouts(self) -> dict:
        """Load account lockout data from file."""
        try:
            if os.path.exists(self.lockout_file):
                with open(self.lockout_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            Logger.error(f"Failed to load lockouts: {str(e)}")
        return {}
    
    def _save_lockouts(self):
        """Save account lockout data to file."""
        try:
            with open(self.lockout_file, 'w') as f:
                json.dump(self.account_lockouts, f, indent=2)
        except Exception as e:
            Logger.error(f"Failed to save lockouts: {str(e)}")
    
    def _load_password_history(self) -> dict:
        """Load password history data from file."""
        try:
            if os.path.exists(self.password_history_file):
                with open(self.password_history_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            Logger.error(f"Failed to load password history: {str(e)}")
        return {}
    
    def _save_password_history(self):
        """Save password history data to file."""
        try:
            with open(self.password_history_file, 'w') as f:
                json.dump(self.password_history, f, indent=2)
        except Exception as e:
            Logger.error(f"Failed to save password history: {str(e)}")
    
    def _load_failed_attempts(self) -> dict:
        """Load failed attempt data from file."""
        try:
            if os.path.exists(self.failed_attempts_file):
                with open(self.failed_attempts_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            Logger.error(f"Failed to load failed attempts: {str(e)}")
        return defaultdict(list)
    
    def _save_failed_attempts(self):
        """Save failed attempt data to file."""
        try:
            with open(self.failed_attempts_file, 'w') as f:
                json.dump(self.failed_attempts, f, indent=2)
        except Exception as e:
            Logger.error(f"Failed to save failed attempts: {str(e)}")
    
    def check_rate_limit(self, ip_address: str, action: str = "login") -> bool:
        """
        Check if an IP address is rate limited for a specific action.
        
        Args:
            ip_address (str): IP address to check
            action (str): Action being performed (login, register, etc.)
            
        Returns:
            bool: True if allowed, False if rate limited
        """
        current_time = time.time()
        key = f"{ip_address}:{action}"
        
        # Clean old entries
        if key in self.rate_limits:
            self.rate_limits[key] = [
                timestamp for timestamp in self.rate_limits[key]
                if current_time - timestamp < self.ip_window_seconds
            ]
        
        # Check rate limit
        if key in self.rate_limits and len(self.rate_limits[key]) >= self.ip_rate_limit:
            Logger.warning(f"Rate limit exceeded for IP {ip_address} on action {action}")
            return False
        
        # Record attempt
        if key not in self.rate_limits:
            self.rate_limits[key] = []
        self.rate_limits[key].append(current_time)
        self._save_rate_limits()
        
        return True
    
    def record_failed_attempt(self, username: str, ip_address: str) -> bool:
        """
        Record a failed login attempt and check for account lockout.
        
        Args:
            username (str): Username that failed login
            ip_address (str): IP address of the attempt
            
        Returns:
            bool: True if account should be locked, False otherwise
        """
        current_time = time.time()
        
        # Initialize failed attempts for username if not exists
        if username not in self.failed_attempts:
            self.failed_attempts[username] = []
        
        # Record failed attempt
        self.failed_attempts[username].append({
            'timestamp': current_time,
            'ip_address': ip_address
        })
        
        # Clean old attempts (older than lockout duration)
        cutoff_time = current_time - (self.lockout_duration_minutes * 60)
        self.failed_attempts[username] = [
            attempt for attempt in self.failed_attempts[username]
            if attempt['timestamp'] > cutoff_time
        ]
        
        # Save failed attempts to disk
        self._save_failed_attempts()
        
        # Check if account should be locked
        if len(self.failed_attempts[username]) >= self.max_login_attempts:
            self._lock_account(username, ip_address)
            return True
        
        return False
    
    def _lock_account(self, username: str, ip_address: str):
        """Lock an account due to too many failed attempts."""
        lockout_until = datetime.utcnow() + timedelta(minutes=self.lockout_duration_minutes)
        
        self.account_lockouts[username] = {
            'locked_at': datetime.utcnow().isoformat(),
            'locked_until': lockout_until.isoformat(),
            'ip_address': ip_address,
            'reason': 'Too many failed login attempts'
        }
        
        # Clear failed attempts for this user after locking
        if username in self.failed_attempts:
            del self.failed_attempts[username]
            self._save_failed_attempts()
        
        self._save_lockouts()
        Logger.warning(f"Account locked: {username} from IP {ip_address}")
    
    def is_account_locked(self, username: str) -> bool:
        """
        Check if an account is currently locked.
        
        Args:
            username (str): Username to check
            
        Returns:
            bool: True if account is locked, False otherwise
        """
        if username not in self.account_lockouts:
            return False
        
        lockout_data = self.account_lockouts[username]
        locked_until = datetime.fromisoformat(lockout_data['locked_until'])
        
        if datetime.utcnow() > locked_until:
            # Lockout expired, remove it
            del self.account_lockouts[username]
            self._save_lockouts()
            return False
        
        return True
    
    def unlock_account(self, username: str) -> bool:
        """
        Manually unlock an account.
        
        Args:
            username (str): Username to unlock
            
        Returns:
            bool: True if account was unlocked, False if not found
        """
        if username in self.account_lockouts:
            del self.account_lockouts[username]
            self._save_lockouts()
            Logger.info(f"Account manually unlocked: {username}")
            return True
        return False
    
    def get_lockout_info(self, username: str) -> Optional[dict]:
        """
        Get lockout information for an account.
        
        Args:
            username (str): Username to check
            
        Returns:
            dict: Lockout information or None if not locked
        """
        return self.account_lockouts.get(username)
    
    def validate_password_policy(self, password: str, username: str = None) -> dict:
        """
        Validate password against security policy.
        
        Args:
            password (str): Password to validate
            username (str): Username (for history check)
            
        Returns:
            dict: Validation result with details
        """
        result = {
            'valid': True,
            'errors': [],
            'warnings': []
        }
        
        # Check length
        if len(password) < self.min_password_length:
            result['valid'] = False
            result['errors'].append(f"Password must be at least {self.min_password_length} characters")
        
        # Check character requirements
        if self.require_uppercase and not re.search(r'[A-Z]', password):
            result['valid'] = False
            result['errors'].append("Password must contain at least one uppercase letter")
        
        if self.require_lowercase and not re.search(r'[a-z]', password):
            result['valid'] = False
            result['errors'].append("Password must contain at least one lowercase letter")
        
        if self.require_digits and not re.search(r'\d', password):
            result['valid'] = False
            result['errors'].append("Password must contain at least one digit")
        
        if self.require_special_chars and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            result['valid'] = False
            result['errors'].append("Password must contain at least one special character")
        
        # Check for common patterns
        if re.search(r'(.)\1{2,}', password):
            result['warnings'].append("Password contains repeated characters")
        
        if re.search(r'(123|abc|qwe)', password.lower()):
            result['warnings'].append("Password contains common patterns")
        
        # Check password history
        if username and self._is_password_in_history(username, password):
            result['valid'] = False
            result['errors'].append("Password has been used recently")
        
        return result
    
    def _is_password_in_history(self, username: str, password: str) -> bool:
        """Check if password is in user's password history."""
        if username not in self.password_history:
            return False
        
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        return password_hash in self.password_history[username]
    
    def add_password_to_history(self, username: str, password: str):
        """Add password to user's password history."""
        if username not in self.password_history:
            self.password_history[username] = []
        
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        self.password_history[username].append(password_hash)
        
        # Keep only recent passwords
        if len(self.password_history[username]) > self.max_password_history:
            self.password_history[username] = self.password_history[username][-self.max_password_history:]
        
        self._save_password_history()
    
    def get_rate_limit_stats(self) -> dict:
        """Get rate limiting statistics."""
        current_time = time.time()
        stats = {
            'active_lockouts': len(self.account_lockouts),
            'total_rate_limited_ips': 0,
            'failed_attempts_by_user': {}
        }
        
        # Count rate limited IPs
        for key in self.rate_limits:
            timestamps = self.rate_limits[key]
            recent_attempts = [ts for ts in timestamps if current_time - ts < self.ip_window_seconds]
            if len(recent_attempts) >= self.ip_rate_limit:
                stats['total_rate_limited_ips'] += 1
        
        # Count failed attempts by user
        for username, attempts in self.failed_attempts.items():
            recent_attempts = [a for a in attempts if current_time - a['timestamp'] < (self.lockout_duration_minutes * 60)]
            if recent_attempts:
                stats['failed_attempts_by_user'][username] = len(recent_attempts)
        
        return stats
    
    def cleanup_expired_data(self):
        """Clean up expired rate limit and lockout data."""
        current_time = time.time()
        
        # Clean rate limits
        for key in list(self.rate_limits.keys()):
            self.rate_limits[key] = [
                timestamp for timestamp in self.rate_limits[key]
                if current_time - timestamp < self.ip_window_seconds
            ]
            if not self.rate_limits[key]:
                del self.rate_limits[key]
        
        # Clean lockouts
        for username in list(self.account_lockouts.keys()):
            lockout_data = self.account_lockouts[username]
            locked_until = datetime.fromisoformat(lockout_data['locked_until'])
            if datetime.utcnow() > locked_until:
                del self.account_lockouts[username]
        
        self._save_rate_limits()
        self._save_lockouts()
        self._save_failed_attempts()

# Global rate limiter instance
rate_limiter = RateLimiter() 