"""
Filename: integrity_manager.py
Author: Mobeen Ali
Date: July 2025

Purpose:
--------
Implements data and software integrity protection for the Secure CLI E-Commerce Application.
Addresses OWASP A08: Software and Data Integrity Failures by providing integrity checks,
digital signatures, secure update mechanisms, and tamper detection.

Security Features:
------------------
- Data integrity validation using checksums
- Digital signature verification
- Secure update mechanisms
- Tamper detection and alerting
- Supply chain security validation
- Code integrity checks
- File integrity monitoring
- Secure deployment validation

Usage:
-------
- IntegrityManager.validate_data_integrity(data, checksum) -> bool
- IntegrityManager.generate_checksum(data) -> str
- IntegrityManager.verify_digital_signature(data, signature) -> bool
- IntegrityManager.monitor_file_integrity(file_path) -> dict
"""

import json
import os
import hashlib
import hmac
import base64
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.fernet import Fernet
from app.core.logger import Logger

class IntegrityManager:
    """Data and software integrity protection."""
    
    def __init__(self):
        self.integrity_file = "data/integrity_checksums.json"
        self.signature_file = "data/digital_signatures.json"
        self.monitoring_file = "data/file_monitoring.json"
        
        # Integrity configuration
        self.checksum_algorithm = "sha256"
        self.signature_algorithm = "RSA"
        self.key_size = 2048
        
        # File monitoring
        self.monitored_files = [
                    "data/users.json",
        "data/products.json",
        "data/sessions.json",
            "data/crypto_keys.json",
            "data/security_config.json"
        ]
        
        # Load data
        self.integrity_checksums = self._load_integrity_checksums()
        self.digital_signatures = self._load_digital_signatures()
        self.file_monitoring = self._load_file_monitoring()
        
        # Generate or load keys
        self.private_key, self.public_key = self._load_or_generate_keys()
    
    def _load_integrity_checksums(self) -> dict:
        """Load integrity checksums from file."""
        try:
            if os.path.exists(self.integrity_file):
                with open(self.integrity_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            Logger.error(f"Failed to load integrity checksums: {str(e)}")
        return {}
    
    def _save_integrity_checksums(self):
        """Save integrity checksums to file."""
        try:
            with open(self.integrity_file, 'w') as f:
                json.dump(self.integrity_checksums, f, indent=2)
        except Exception as e:
            Logger.error(f"Failed to save integrity checksums: {str(e)}")
    
    def _load_digital_signatures(self) -> dict:
        """Load digital signatures from file."""
        try:
            if os.path.exists(self.signature_file):
                with open(self.signature_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            Logger.error(f"Failed to load digital signatures: {str(e)}")
        return {}
    
    def _save_digital_signatures(self):
        """Save digital signatures to file."""
        try:
            with open(self.signature_file, 'w') as f:
                json.dump(self.digital_signatures, f, indent=2)
        except Exception as e:
            Logger.error(f"Failed to save digital signatures: {str(e)}")
    
    def _load_file_monitoring(self) -> dict:
        """Load file monitoring data from file."""
        try:
            if os.path.exists(self.monitoring_file):
                with open(self.monitoring_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            Logger.error(f"Failed to load file monitoring: {str(e)}")
        return {}
    
    def _save_file_monitoring(self):
        """Save file monitoring data to file."""
        try:
            with open(self.monitoring_file, 'w') as f:
                json.dump(self.file_monitoring, f, indent=2)
        except Exception as e:
            Logger.error(f"Failed to save file monitoring: {str(e)}")
    
    def _load_or_generate_keys(self) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """Load existing keys or generate new ones."""
        private_key_file = "private_key.pem"
        public_key_file = "public_key.pem"
        
        try:
            # Try to load existing keys
            if os.path.exists(private_key_file) and os.path.exists(public_key_file):
                with open(private_key_file, 'rb') as f:
                    private_key = serialization.load_pem_private_key(
                        f.read(),
                        password=None
                    )
                with open(public_key_file, 'rb') as f:
                    public_key = serialization.load_pem_public_key(f.read())
                
                Logger.info("Loaded existing integrity keys")
                return private_key, public_key
        except Exception as e:
            Logger.warning(f"Failed to load existing keys: {str(e)}")
        
        # Generate new keys
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size
        )
        public_key = private_key.public_key()
        
        # Save keys
        with open(private_key_file, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        with open(public_key_file, 'wb') as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        
        Logger.info("Generated new integrity keys")
        return private_key, public_key
    
    def generate_checksum(self, data: str) -> str:
        """
        Generate checksum for data.
        
        Args:
            data (str): Data to generate checksum for
            
        Returns:
            str: Hexadecimal checksum
        """
        if self.checksum_algorithm == "sha256":
            return hashlib.sha256(data.encode()).hexdigest()
        elif self.checksum_algorithm == "sha512":
            return hashlib.sha512(data.encode()).hexdigest()
        else:
            return hashlib.md5(data.encode()).hexdigest()
    
    def validate_data_integrity(self, data: str, expected_checksum: str) -> bool:
        """
        Validate data integrity using checksum.
        
        Args:
            data (str): Data to validate
            expected_checksum (str): Expected checksum
            
        Returns:
            bool: True if integrity is valid, False otherwise
        """
        actual_checksum = self.generate_checksum(data)
        is_valid = actual_checksum == expected_checksum
        
        if not is_valid:
            Logger.warning(f"Data integrity check failed. Expected: {expected_checksum}, Got: {actual_checksum}")
        
        return is_valid
    
    def create_digital_signature(self, data: str) -> str:
        """
        Create digital signature for data.
        
        Args:
            data (str): Data to sign
            
        Returns:
            str: Base64 encoded signature
        """
        signature = self.private_key.sign(
            data.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode()
    
    def verify_digital_signature(self, data: str, signature: str) -> bool:
        """
        Verify digital signature for data.
        
        Args:
            data (str): Data to verify
            signature (str): Base64 encoded signature
            
        Returns:
            bool: True if signature is valid, False otherwise
        """
        try:
            signature_bytes = base64.b64decode(signature.encode())
            self.public_key.verify(
                signature_bytes,
                data.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            Logger.warning(f"Digital signature verification failed: {str(e)}")
            return False
    
    def store_data_with_integrity(self, key: str, data: str) -> bool:
        """
        Store data with integrity checks and digital signature.
        
        Args:
            key (str): Key for storing data
            data (str): Data to store
            
        Returns:
            bool: True if stored successfully, False otherwise
        """
        try:
            # Generate checksum
            checksum = self.generate_checksum(data)
            
            # Create digital signature
            signature = self.create_digital_signature(data)
            
            # Store integrity information
            self.integrity_checksums[key] = {
                'checksum': checksum,
                'algorithm': self.checksum_algorithm,
                'created_at': datetime.utcnow().isoformat()
            }
            
            self.digital_signatures[key] = {
                'signature': signature,
                'algorithm': self.signature_algorithm,
                'created_at': datetime.utcnow().isoformat()
            }
            
            self._save_integrity_checksums()
            self._save_digital_signatures()
            
            Logger.info(f"Stored data with integrity protection: {key}")
            return True
            
        except Exception as e:
            Logger.error(f"Failed to store data with integrity: {str(e)}")
            return False
    
    def validate_stored_data_integrity(self, key: str, data: str) -> bool:
        """
        Validate integrity of stored data.
        
        Args:
            key (str): Key for stored data
            data (str): Data to validate
            
        Returns:
            bool: True if integrity is valid, False otherwise
        """
        if key not in self.integrity_checksums:
            Logger.warning(f"No integrity data found for key: {key}")
            return False
        
        # Validate checksum
        expected_checksum = self.integrity_checksums[key]['checksum']
        if not self.validate_data_integrity(data, expected_checksum):
            return False
        
        # Validate digital signature
        if key in self.digital_signatures:
            expected_signature = self.digital_signatures[key]['signature']
            if not self.verify_digital_signature(data, expected_signature):
                return False
        
        return True
    
    def monitor_file_integrity(self, file_path: str) -> dict:
        """
        Monitor file integrity and detect changes.
        
        Args:
            file_path (str): Path to file to monitor
            
        Returns:
            dict: Monitoring results
        """
        if not os.path.exists(file_path):
            return {
                'file_exists': False,
                'integrity_valid': False,
                'last_modified': None,
                'checksum': None,
                'changes_detected': False
            }
        
        try:
            # Get file stats
            stat = os.stat(file_path)
            last_modified = datetime.fromtimestamp(stat.st_mtime)
            
            # Read file content
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Generate current checksum
            current_checksum = self.generate_checksum(content)
            
            # Check for previous monitoring data
            monitoring_key = f"file:{file_path}"
            changes_detected = False
            
            if monitoring_key in self.file_monitoring:
                previous_data = self.file_monitoring[monitoring_key]
                previous_checksum = previous_data.get('checksum')
                previous_modified = datetime.fromisoformat(previous_data.get('last_modified'))
                
                if current_checksum != previous_checksum:
                    changes_detected = True
                    Logger.warning(f"File integrity change detected: {file_path}")
            
            # Update monitoring data
            self.file_monitoring[monitoring_key] = {
                'checksum': current_checksum,
                'last_modified': last_modified.isoformat(),
                'size': stat.st_size,
                'monitored_at': datetime.utcnow().isoformat()
            }
            
            self._save_file_monitoring()
            
            return {
                'file_exists': True,
                'integrity_valid': not changes_detected,
                'last_modified': last_modified.isoformat(),
                'checksum': current_checksum,
                'changes_detected': changes_detected
            }
            
        except Exception as e:
            Logger.error(f"Failed to monitor file integrity: {str(e)}")
            return {
                'file_exists': True,
                'integrity_valid': False,
                'last_modified': None,
                'checksum': None,
                'changes_detected': False,
                'error': str(e)
            }
    
    def monitor_all_critical_files(self) -> dict:
        """
        Monitor integrity of all critical files.
        
        Returns:
            dict: Monitoring results for all files
        """
        results = {}
        
        for file_path in self.monitored_files:
            if os.path.exists(file_path):
                results[file_path] = self.monitor_file_integrity(file_path)
            else:
                results[file_path] = {
                    'file_exists': False,
                    'integrity_valid': False,
                    'last_modified': None,
                    'checksum': None,
                    'changes_detected': False
                }
        
        return results
    
    def validate_supply_chain_integrity(self) -> dict:
        """
        Validate supply chain integrity by checking dependencies.
        
        Returns:
            dict: Supply chain validation results
        """
        results = {
            'valid': True,
            'checks': {},
            'warnings': [],
            'errors': []
        }
        
        # Check requirements.txt integrity
        if os.path.exists('requirements.txt'):
            with open('requirements.txt', 'r') as f:
                requirements_content = f.read()
            
            requirements_checksum = self.generate_checksum(requirements_content)
            results['checks']['requirements.txt'] = {
                'checksum': requirements_checksum,
                'valid': True
            }
        
        # Check key files integrity
        key_files = ['users.json', 'products.json', 'security_config.json']
        for file_path in key_files:
            if os.path.exists(file_path):
                file_result = self.monitor_file_integrity(file_path)
                results['checks'][file_path] = file_result
                
                if file_result.get('changes_detected', False):
                    results['warnings'].append(f"File changes detected: {file_path}")
        
        # Check for suspicious patterns
        for file_path in self.monitored_files:
            if os.path.exists(file_path):
                try:
                    with open(file_path, 'r') as f:
                        content = f.read()
                    
                    # Check for suspicious patterns
                    suspicious_patterns = [
                        'eval(', 'exec(', 'os.system(', 'subprocess.call(',
                        'import os', 'import subprocess', '__import__('
                    ]
                    
                    for pattern in suspicious_patterns:
                        if pattern in content:
                            results['warnings'].append(f"Suspicious pattern found in {file_path}: {pattern}")
                            results['valid'] = False
                            
                except Exception as e:
                    results['errors'].append(f"Failed to check {file_path}: {str(e)}")
                    results['valid'] = False
        
        return results
    
    def get_integrity_statistics(self) -> dict:
        """Get integrity monitoring statistics."""
        stats = {
            'total_monitored_files': len(self.monitored_files),
            'files_with_integrity_data': len(self.integrity_checksums),
            'files_with_signatures': len(self.digital_signatures),
            'recent_changes': 0,
            'integrity_violations': 0
        }
        
        # Count recent changes and violations
        for file_path in self.monitored_files:
            monitoring_key = f"file:{file_path}"
            if monitoring_key in self.file_monitoring:
                file_data = self.file_monitoring[monitoring_key]
                monitored_at = datetime.fromisoformat(file_data.get('monitored_at', '2020-01-01'))
                
                if datetime.utcnow() - monitored_at < timedelta(hours=24):
                    stats['recent_changes'] += 1
        
        return stats
    
    def cleanup_old_integrity_data(self):
        """Clean up old integrity monitoring data."""
        current_time = datetime.utcnow()
        cutoff_time = current_time - timedelta(days=30)
        
        # Clean old file monitoring data
        for key in list(self.file_monitoring.keys()):
            file_data = self.file_monitoring[key]
            monitored_at = datetime.fromisoformat(file_data.get('monitored_at', '2020-01-01'))
            
            if monitored_at < cutoff_time:
                del self.file_monitoring[key]
        
        self._save_file_monitoring()
        Logger.info("Cleaned up old integrity monitoring data")

# Global integrity manager instance
integrity_manager = IntegrityManager() 