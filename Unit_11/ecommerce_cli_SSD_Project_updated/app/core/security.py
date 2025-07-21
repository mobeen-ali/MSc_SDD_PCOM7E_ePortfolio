"""
Filename: security.py
Author: Mobeen Ali
Date: July 2025

Purpose:
--------
Provides a simple configuration switch to enable or disable security features
(e.g., encryption, 2FA, auditing) in the CLI E-Commerce Application.

Used primarily for testing and educational purposes to simulate insecure states.

Security Policy:
----------------
- Security is enabled by default (if config file doesn't exist)
- Only users with the "admin" role can toggle the security state
- Settings are persisted in a JSON config file for consistency

Usage:
-------
- SecurityManager.is_security_enabled() → bool
- SecurityManager.toggle_security(user_role) → bool (new state)

File:
------
security_config.json  → {"security": true/false}
"""


import json
import os

SECURITY_CONFIG_FILE = "data/security_config.json"


class SecurityManager:
    """
    Controls global security state for the application.
    """
    @staticmethod
    def is_security_enabled():
        """
        Checks whether security features are currently enabled.

        Returns:
            bool: True if enabled, False if disabled
        """
        if not os.path.exists(SECURITY_CONFIG_FILE):
            return True  # Default to secure if no config found
        with open(SECURITY_CONFIG_FILE, "r") as f:
            return json.load(f).get("security", True)

    @staticmethod
    def toggle_security(user_role: str):
        """
        Toggles the security setting (ON/OFF). Only accessible by admin users.

        Args:
            user_role (str): The role of the current user (must be 'admin')

        Returns:
            bool: The new security state (True = enabled, False = disabled)

        Raises:
            PermissionError: If the user is not an admin
        """
        if user_role != "admin":
            raise PermissionError("Only admins can toggle security.")

        current = SecurityManager.is_security_enabled()
        new_state = not current
        with open(SECURITY_CONFIG_FILE, "w") as f:
            json.dump({"security": new_state}, f, indent=4)
        return new_state
