"""
Filename: session.py
Author: Mobeen Ali
Date: July 2025

Purpose:
--------
Implements secure session management for the Secure CLI E-Commerce Application.
Addresses OWASP A01: Broken Access Control by providing proper session handling,
JWT token management, and session timeout functionality.

Security Features:
------------------
- JWT-based session tokens with expiration
- Session timeout and automatic logout
- Secure token generation and validation
- Session storage with encryption
- Role-based session permissions

Usage:
-------
- SessionManager.create_session(user) -> str (session_token)
- SessionManager.validate_session(token) -> dict (session_data)
- SessionManager.invalidate_session(token) -> bool
- SessionManager.get_active_sessions() -> list
"""

import jwt
import time
import uuid
import json
import os
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from app.core.logger import Logger
from app.core.storage import load_key

# Session configuration
SESSION_TIMEOUT_MINUTES = 30
JWT_SECRET = os.environ.get('JWT_SECRET', 'your-secret-key-change-in-production')
SESSIONS_FILE = "data/sessions.json"

class SessionManager:
    """
    Manages user sessions with JWT tokens and secure storage.
    """
    
    def __init__(self):
        """Initialize session manager with encryption key."""
        self.fernet = Fernet(load_key())
        self._load_sessions()
    
    def _load_sessions(self):
        """Load encrypted sessions from file."""
        if not os.path.exists(SESSIONS_FILE):
            self.sessions = {}
            return
        
        try:
            with open(SESSIONS_FILE, 'rb') as f:
                encrypted_data = f.read()
                decrypted_data = self.fernet.decrypt(encrypted_data)
                self.sessions = json.loads(decrypted_data.decode())
        except Exception as e:
            Logger.error(f"Failed to load sessions: {str(e)}")
            self.sessions = {}
    
    def _save_sessions(self):
        """Save encrypted sessions to file."""
        try:
            data = json.dumps(self.sessions)
            encrypted_data = self.fernet.encrypt(data.encode())
            with open(SESSIONS_FILE, 'wb') as f:
                f.write(encrypted_data)
        except Exception as e:
            Logger.error(f"Failed to save sessions: {str(e)}")
    
    def create_session(self, user_data: dict) -> str:
        """
        Create a new session for a user.
        
        Args:
            user_data (dict): User information including username and role
            
        Returns:
            str: JWT session token
        """
        session_id = str(uuid.uuid4())
        current_time = datetime.utcnow()
        expiration_time = current_time + timedelta(minutes=SESSION_TIMEOUT_MINUTES)
        
        # Create JWT payload
        payload = {
            'session_id': session_id,
            'username': user_data['username'],
            'role': user_data['role'],
            'iat': current_time,
            'exp': expiration_time,
            'jti': str(uuid.uuid4())  # JWT ID for uniqueness
        }
        
        # Generate JWT token
        token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
        
        # Store session data
        session_data = {
            'session_id': session_id,
            'username': user_data['username'],
            'role': user_data['role'],
            'created_at': current_time.isoformat(),
            'expires_at': expiration_time.isoformat(),
            'last_activity': current_time.isoformat(),
            'is_active': True
        }
        
        self.sessions[session_id] = session_data
        self._save_sessions()
        
        Logger.info(f"Session created for user: {user_data['username']}")
        return token
    
    def validate_session(self, token: str) -> dict:
        """
        Validate a session token and return session data.
        
        Args:
            token (str): JWT session token
            
        Returns:
            dict: Session data if valid, None otherwise
        """
        try:
            # Decode and verify JWT
            payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            session_id = payload['session_id']
            
            # Check if session exists and is active
            if session_id not in self.sessions:
                Logger.warning(f"Session not found: {session_id}")
                return None
            
            session_data = self.sessions[session_id]
            if not session_data['is_active']:
                Logger.warning(f"Session inactive: {session_id}")
                return None
            
            # Check if session has expired using stored expiration time
            expires_at = datetime.fromisoformat(session_data['expires_at'])
            if datetime.utcnow() > expires_at:
                Logger.warning(f"Session expired: {session_id}")
                # Mark session as inactive
                session_data['is_active'] = False
                self._save_sessions()
                return None
            
            # Update last activity
            session_data['last_activity'] = datetime.utcnow().isoformat()
            self._save_sessions()
            
            return session_data
            
        except jwt.ExpiredSignatureError:
            Logger.warning("Session token expired")
            return None
        except jwt.InvalidTokenError as e:
            Logger.warning(f"Invalid session token: {str(e)}")
            return None
        except Exception as e:
            Logger.error(f"Session validation error: {str(e)}")
            return None
    
    def invalidate_session(self, token: str) -> bool:
        """
        Invalidate a session token.
        
        Args:
            token (str): JWT session token
            
        Returns:
            bool: True if session was invalidated, False otherwise
        """
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            session_id = payload['session_id']
            
            if session_id in self.sessions:
                self.sessions[session_id]['is_active'] = False
                self._save_sessions()
                Logger.info(f"Session invalidated: {session_id}")
                return True
            
            return False
            
        except jwt.InvalidTokenError:
            return False
        except Exception as e:
            Logger.error(f"Session invalidation error: {str(e)}")
            return False
    
    def refresh_session(self, token: str) -> str:
        """
        Refresh a session token by extending its expiration.
        
        Args:
            token (str): Current JWT session token
            
        Returns:
            str: New JWT session token
        """
        session_data = self.validate_session(token)
        if not session_data:
            return None
        
        # Create new session with extended expiration
        user_data = {
            'username': session_data['username'],
            'role': session_data['role']
        }
        
        # Invalidate old session
        self.invalidate_session(token)
        
        # Create new session
        return self.create_session(user_data)
    
    def get_active_sessions(self) -> list:
        """
        Get all active sessions.
        
        Returns:
            list: List of active session data
        """
        active_sessions = []
        current_time = datetime.utcnow()
        
        for session_id, session_data in self.sessions.items():
            if session_data['is_active']:
                expires_at = datetime.fromisoformat(session_data['expires_at'])
                if current_time <= expires_at:
                    active_sessions.append(session_data)
        
        return active_sessions
    
    def cleanup_expired_sessions(self):
        """Remove expired sessions from storage."""
        current_time = datetime.utcnow()
        expired_sessions = []
        
        for session_id, session_data in self.sessions.items():
            expires_at = datetime.fromisoformat(session_data['expires_at'])
            if current_time > expires_at:
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            del self.sessions[session_id]
        
        if expired_sessions:
            self._save_sessions()
            Logger.info(f"Cleaned up {len(expired_sessions)} expired sessions")

# Global session manager instance
session_manager = SessionManager() 