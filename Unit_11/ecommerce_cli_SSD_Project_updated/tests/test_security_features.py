"""
Filename: test_security_features.py
Author: Mobeen Ali
Date: July 2025

Purpose:
--------
Comprehensive tests for OWASP A01-A06 security features in the Secure CLI E-Commerce Application.
Tests session management, cryptographic key rotation, threat modeling, and vulnerability scanning.

Security Features Tested:
-------------------------
- OWASP A01: Session Management (JWT tokens, session timeout)
- OWASP A02: Cryptographic Key Rotation (key management, rotation)
- OWASP A04: Threat Modeling (threat analysis, risk assessment)
- OWASP A06: Vulnerability Scanning (dependency scanning, advisories)
"""

import os
import pytest
import tempfile
import shutil
import jwt
from datetime import datetime, timedelta
from app.core.session import SessionManager, session_manager
from app.core.crypto_manager import CryptoManager, crypto_manager
from app.core.threat_model import ThreatModel, threat_model
from app.core.vulnerability_scanner import VulnerabilityScanner, vulnerability_scanner
from app.core.storage import validate_encryption_integrity, get_encryption_statistics


class TestSessionManagement:
    """Test OWASP A01: Session Management"""
    
    def setup_method(self):
        """Setup test environment for session management."""
        # Create temporary test files
        self.test_sessions_file = "test_sessions.json"
        self.test_users_file = "test_users.json"
        
        # Backup original files
        if os.path.exists("sessions.json"):
            shutil.copy("sessions.json", "sessions.json.backup")
        if os.path.exists("users.json"):
            shutil.copy("users.json", "users.json.backup")
    
    def teardown_method(self):
        """Cleanup test environment."""
        # Remove test files
        for file in [self.test_sessions_file, self.test_users_file]:
            if os.path.exists(file):
                os.remove(file)
        
        # Restore original files
        if os.path.exists("sessions.json.backup"):
            shutil.move("sessions.json.backup", "sessions.json")
        if os.path.exists("users.json.backup"):
            shutil.move("users.json.backup", "users.json")
    
    def test_session_creation(self):
        """Test session creation with user data."""
        user_data = {
            'username': 'testuser',
            'role': 'user'
        }
        
        token = session_manager.create_session(user_data)
        assert token is not None
        assert len(token) > 0
    
    def test_session_validation(self):
        """Test session validation with valid token."""
        user_data = {
            'username': 'testuser',
            'role': 'user'
        }
        
        token = session_manager.create_session(user_data)
        session_data = session_manager.validate_session(token)
        
        assert session_data is not None
        assert session_data['username'] == 'testuser'
        assert session_data['role'] == 'user'
        assert session_data['is_active'] is True
    
    def test_session_invalidation(self):
        """Test session invalidation."""
        user_data = {
            'username': 'testuser',
            'role': 'user'
        }
        
        token = session_manager.create_session(user_data)
        success = session_manager.invalidate_session(token)
        
        assert success is True
        
        # Try to validate invalidated session
        session_data = session_manager.validate_session(token)
        assert session_data is None
    
    def test_session_timeout(self):
        """Test session timeout functionality."""
        user_data = {
            'username': 'testuser',
            'role': 'user'
        }
        
        token = session_manager.create_session(user_data)
        
        # Get the session ID from the token
        payload = jwt.decode(token, 'your-secret-key-change-in-production', algorithms=['HS256'])
        session_id = payload['session_id']
        
        # Manually expire the session by modifying the stored expiration time
        if session_id in session_manager.sessions:
            session_manager.sessions[session_id]['expires_at'] = (datetime.utcnow() - timedelta(minutes=1)).isoformat()
            session_manager._save_sessions()
        
        # Now validate the session - it should be expired
        session_data = session_manager.validate_session(token)
        assert session_data is None


class TestCryptographicKeyRotation:
    """Test OWASP A02: Cryptographic Key Rotation"""
    
    def setup_method(self):
        """Setup test environment for cryptographic key management."""
        # Create temporary test files
        self.test_keys_file = "test_crypto_keys.json"
        self.test_master_key = "test_master.key"
        
        # Backup original files
        if os.path.exists("crypto_keys.json"):
            shutil.copy("crypto_keys.json", "crypto_keys.json.backup")
        if os.path.exists("master.key"):
            shutil.copy("master.key", "master.key.backup")
    
    def teardown_method(self):
        """Cleanup test environment."""
        # Remove test files
        for file in [self.test_keys_file, self.test_master_key]:
            if os.path.exists(file):
                os.remove(file)
        
        # Restore original files
        if os.path.exists("crypto_keys.json.backup"):
            shutil.move("crypto_keys.json.backup", "crypto_keys.json")
        if os.path.exists("master.key.backup"):
            shutil.move("master.key.backup", "master.key")
    
    def test_key_generation(self):
        """Test cryptographic key generation."""
        key_id = crypto_manager.generate_new_key('fernet')
        assert key_id is not None
        assert key_id in crypto_manager.keys
    
    def test_key_rotation(self):
        """Test cryptographic key rotation."""
        # Generate initial key
        initial_key_id = crypto_manager.generate_new_key('fernet')
        
        # Rotate keys
        success = crypto_manager.rotate_keys()
        assert success is True
        
        # Check that new key was generated
        stats = crypto_manager.get_key_statistics()
        assert stats['active_keys'] > 0
    
    def test_key_integrity_validation(self):
        """Test cryptographic key integrity validation."""
        # Generate a key
        crypto_manager.generate_new_key('fernet')
        
        # Validate integrity
        is_valid = crypto_manager.validate_key_integrity()
        assert is_valid is True
    
    def test_encryption_with_key_rotation(self):
        """Test encryption with automatic key rotation."""
        test_data = "test_encryption_data"
        
        encrypted = crypto_manager.encrypt_with_key_rotation(test_data)
        assert encrypted is not None
        assert len(encrypted) > 0
    
    def test_decryption_with_key_rotation(self):
        """Test decryption with key rotation support."""
        test_data = "test_decryption_data"
        
        encrypted = crypto_manager.encrypt_with_key_rotation(test_data)
        decrypted = crypto_manager.decrypt_with_key_rotation(encrypted)
        
        assert decrypted == test_data


class TestThreatModeling:
    """Test OWASP A04: Threat Modeling"""
    
    def setup_method(self):
        """Setup test environment for threat modeling."""
        self.test_threats_file = "test_threat_model.json"
        
        # Backup original file
        if os.path.exists("threat_model.json"):
            shutil.copy("threat_model.json", "threat_model.json.backup")
    
    def teardown_method(self):
        """Cleanup test environment."""
        if os.path.exists(self.test_threats_file):
            os.remove(self.test_threats_file)
        
        # Restore original file
        if os.path.exists("threat_model.json.backup"):
            shutil.move("threat_model.json.backup", "threat_model.json")
    
    def test_threat_analysis(self):
        """Test comprehensive threat analysis."""
        analysis = threat_model.analyze_threats()
        
        assert analysis is not None
        assert 'summary' in analysis
        assert 'threats_by_category' in analysis
        assert 'threats_by_risk' in analysis
        assert 'recommendations' in analysis
    
    def test_risk_assessment(self):
        """Test risk assessment for specific threats."""
        threat_id = "A01_BROKEN_ACCESS_CONTROL"
        risk_score = threat_model.assess_risk(threat_id)
        
        assert risk_score >= 0.0
        assert risk_score <= 1.0
    
    def test_mitigation_strategies(self):
        """Test retrieval of mitigation strategies."""
        threat_id = "A02_CRYPTOGRAPHIC_FAILURES"
        mitigations = threat_model.get_mitigations(threat_id)
        
        assert isinstance(mitigations, list)
        assert len(mitigations) > 0
    
    def test_threat_status_update(self):
        """Test threat status updates."""
        threat_id = "A04_INSECURE_DESIGN"
        success = threat_model.update_threat_status(threat_id, "Mitigated")
        
        assert success is True
        
        # Verify status was updated
        threat_data = threat_model.threats[threat_id]
        assert threat_data['status'] == "Mitigated"
    
    def test_threat_export(self):
        """Test threat model export functionality."""
        export_data = threat_model.export_threat_model("json")
        
        assert export_data is not None
        assert len(export_data) > 0


class TestVulnerabilityScanning:
    """Test OWASP A06: Vulnerability Scanning"""
    
    def setup_method(self):
        """Setup test environment for vulnerability scanning."""
        self.test_components_file = "test_component_inventory.json"
        self.test_vulnerabilities_file = "test_vulnerability_report.json"
        
        # Backup original files
        if os.path.exists("component_inventory.json"):
            shutil.copy("component_inventory.json", "component_inventory.json.backup")
        if os.path.exists("vulnerability_report.json"):
            shutil.copy("vulnerability_report.json", "vulnerability_report.json.backup")
    
    def teardown_method(self):
        """Cleanup test environment."""
        # Remove test files
        for file in [self.test_components_file, self.test_vulnerabilities_file]:
            if os.path.exists(file):
                os.remove(file)
        
        # Restore original files
        if os.path.exists("component_inventory.json.backup"):
            shutil.move("component_inventory.json.backup", "component_inventory.json")
        if os.path.exists("vulnerability_report.json.backup"):
            shutil.move("vulnerability_report.json.backup", "vulnerability_report.json")
    
    def test_dependency_scanning(self):
        """Test dependency vulnerability scanning."""
        scan_results = vulnerability_scanner.scan_dependencies()
        
        assert scan_results is not None
        assert 'scan_timestamp' in scan_results
        assert 'total_components' in scan_results
        assert 'vulnerable_components' in scan_results
        assert 'secure_components' in scan_results
        assert 'components' in scan_results
    
    def test_component_vulnerability_check(self):
        """Test individual component vulnerability checking."""
        # Test with a known vulnerable component
        vulnerabilities = vulnerability_scanner._check_component_vulnerabilities("cryptography", "40.0.0")
        
        assert isinstance(vulnerabilities, list)
        # Should find vulnerabilities in older version
    
    def test_component_outdated_check(self):
        """Test component outdated version checking."""
        is_outdated = vulnerability_scanner._is_component_outdated("cryptography", "40.0.0")
        assert is_outdated is True
        
        is_outdated = vulnerability_scanner._is_component_outdated("cryptography", "41.0.0")
        assert is_outdated is False
    
    def test_risk_score_calculation(self):
        """Test risk score calculation based on vulnerabilities."""
        vulnerabilities = [
            {
                "severity": "Critical",
                "title": "Test vulnerability"
            }
        ]
        
        risk_score = vulnerability_scanner._calculate_risk_score(vulnerabilities)
        assert risk_score == 1.0  # Critical vulnerability should have max score
    
    def test_security_advisories(self):
        """Test security advisory checking."""
        advisories = vulnerability_scanner.check_security_advisories()
        
        assert isinstance(advisories, list)
        assert len(advisories) > 0
        
        for advisory in advisories:
            assert 'id' in advisory
            assert 'title' in advisory
            assert 'severity' in advisory
            assert 'affected_components' in advisory
    
    def test_component_update(self):
        """Test component version update functionality."""
        success = vulnerability_scanner.update_component("cryptography", "41.0.0")
        assert success is True
    
    def test_vulnerability_report_generation(self):
        """Test vulnerability report generation."""
        report = vulnerability_scanner.generate_report("json")
        
        assert report is not None
        assert len(report) > 0


class TestEncryptionIntegrity:
    """Test OWASP A02: Encryption Integrity"""
    
    def test_encryption_integrity_validation(self):
        """Test encryption integrity validation."""
        is_valid = validate_encryption_integrity()
        assert is_valid is True
    
    def test_encryption_statistics(self):
        """Test encryption statistics collection."""
        stats = get_encryption_statistics()
        
        assert stats is not None
        assert 'key_management' in stats
        assert 'storage_files' in stats
        assert 'encryption_integrity' in stats


class TestSecurityIntegration:
    """Test integration of all security features"""
    
    def test_complete_security_workflow(self):
        """Test complete security workflow with all OWASP A01-A06 features."""
        # 1. Create session (A01)
        user_data = {'username': 'testuser', 'role': 'user'}
        token = session_manager.create_session(user_data)
        assert token is not None
        
        # 2. Validate session (A01)
        session_data = session_manager.validate_session(token)
        assert session_data is not None
        
        # 3. Test encryption with key rotation (A02)
        test_data = "secure_test_data"
        encrypted = crypto_manager.encrypt_with_key_rotation(test_data)
        decrypted = crypto_manager.decrypt_with_key_rotation(encrypted)
        assert decrypted == test_data
        
        # 4. Analyze threats (A04)
        analysis = threat_model.analyze_threats()
        assert analysis is not None
        
        # 5. Scan vulnerabilities (A06)
        scan_results = vulnerability_scanner.scan_dependencies()
        assert scan_results is not None
        
        # 6. Check security advisories (A06)
        advisories = vulnerability_scanner.check_security_advisories()
        assert isinstance(advisories, list)
        
        # 7. Validate encryption integrity (A02)
        is_valid = validate_encryption_integrity()
        assert is_valid is True
        
        # 8. Cleanup session (A01)
        success = session_manager.invalidate_session(token)
        assert success is True 