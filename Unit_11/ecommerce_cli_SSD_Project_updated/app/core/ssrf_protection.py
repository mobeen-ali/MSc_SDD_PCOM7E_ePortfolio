"""
Filename: ssrf_protection.py
Author: Mobeen Ali
Date: July 2025

Purpose:
--------
Implements SSRF protection for the Secure CLI E-Commerce Application.
Addresses OWASP A10: Server-Side Request Forgery by providing URL validation,
network segmentation, request filtering, and SSRF detection.

Security Features:
------------------
- URL validation and allowlisting
- Network segmentation controls
- Request filtering and sanitization
- SSRF attack detection
- IP address validation
- Protocol restrictions
- Port scanning protection
- Internal resource protection

Usage:
-------
- SSRFProtection.validate_url(url) -> dict
- SSRFProtection.is_allowed_domain(domain) -> bool
- SSRFProtection.filter_request(request_data) -> dict
- SSRFProtection.detect_ssrf_attempt(url) -> bool
"""

import json
import os
import re
import socket
import ipaddress
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from app.core.logger import Logger

class SSRFProtection:
    """SSRF protection and URL validation."""
    
    def __init__(self):
        self.config_file = "data/ssrf_config.json"
        
        # Default configuration
        self.allowed_domains = [
            "api.example.com",
            "external-service.com",
            "payment-gateway.com"
        ]
        
        self.allowed_protocols = ["https", "http"]
        self.allowed_ports = [80, 443, 8080, 8443]
        
        # Internal network ranges (RFC 1918)
        self.internal_ranges = [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "0.0.0.0/8"
        ]
        
        # Suspicious patterns
        self.suspicious_patterns = [
            r"localhost",
            r"127\.0\.0\.1",
            r"0\.0\.0\.0",
            r"::1",
            r"file://",
            r"ftp://",
            r"gopher://",
            r"dict://",
            r"ldap://",
            r"tftp://",
            r"ssh://",
            r"telnet://"
        ]
        
        # Load configuration
        self.config = self._load_config()
    
    def _load_config(self) -> dict:
        """Load SSRF protection configuration."""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    # Update instance variables with config
                    self.allowed_domains = config.get('allowed_domains', self.allowed_domains)
                    self.allowed_protocols = config.get('allowed_protocols', self.allowed_protocols)
                    self.allowed_ports = config.get('allowed_ports', self.allowed_ports)
                    return config
        except Exception as e:
            Logger.error(f"Failed to load SSRF config: {str(e)}")
        
        return {
            'allowed_domains': self.allowed_domains,
            'allowed_protocols': self.allowed_protocols,
            'allowed_ports': self.allowed_ports,
            'internal_ranges': self.internal_ranges
        }
    
    def _save_config(self):
        """Save SSRF protection configuration."""
        try:
            config = {
                'allowed_domains': self.allowed_domains,
                'allowed_protocols': self.allowed_protocols,
                'allowed_ports': self.allowed_ports,
                'internal_ranges': self.internal_ranges,
                'last_updated': datetime.utcnow().isoformat()
            }
            
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
        except Exception as e:
            Logger.error(f"Failed to save SSRF config: {str(e)}")
    
    def validate_url(self, url: str) -> dict:
        """
        Validate URL for SSRF protection.
        
        Args:
            url (str): URL to validate
            
        Returns:
            dict: Validation result with details
        """
        result = {
            'valid': True,
            'errors': [],
            'warnings': [],
            'details': {}
        }
        
        try:
            # Parse URL
            parsed_url = urlparse(url)
            
            # Check protocol
            if parsed_url.scheme not in self.allowed_protocols:
                result['valid'] = False
                result['errors'].append(f"Protocol '{parsed_url.scheme}' not allowed")
            
            # Check for suspicious patterns
            if self._contains_suspicious_patterns(url):
                result['valid'] = False
                result['errors'].append("URL contains suspicious patterns")
            
            # Check domain
            domain = parsed_url.netloc.split(':')[0]
            if not self.is_allowed_domain(domain):
                result['valid'] = False
                result['errors'].append(f"Domain '{domain}' not in allowlist")
            
            # Check port
            port = parsed_url.port
            if port and port not in self.allowed_ports:
                result['valid'] = False
                result['errors'].append(f"Port {port} not allowed")
            
            # Check for internal IP addresses
            if self._is_internal_ip(domain):
                result['valid'] = False
                result['errors'].append(f"Domain '{domain}' resolves to internal IP")
            
            # Check for SSRF attempts
            if self.detect_ssrf_attempt(url):
                result['valid'] = False
                result['errors'].append("Potential SSRF attempt detected")
            
            # Add details
            result['details'] = {
                'scheme': parsed_url.scheme,
                'domain': domain,
                'port': port,
                'path': parsed_url.path,
                'query': parsed_url.query
            }
            
        except Exception as e:
            result['valid'] = False
            result['errors'].append(f"URL parsing error: {str(e)}")
        
        return result
    
    def is_allowed_domain(self, domain: str) -> bool:
        """
        Check if domain is in allowlist.
        
        Args:
            domain (str): Domain to check
            
        Returns:
            bool: True if domain is allowed, False otherwise
        """
        # Check exact match
        if domain in self.allowed_domains:
            return True
        
        # Check wildcard patterns
        for allowed_domain in self.allowed_domains:
            if allowed_domain.startswith('*.'):
                wildcard_domain = allowed_domain[2:]
                if domain.endswith('.' + wildcard_domain):
                    return True
        
        return False
    
    def _contains_suspicious_patterns(self, url: str) -> bool:
        """Check if URL contains suspicious patterns."""
        url_lower = url.lower()
        
        for pattern in self.suspicious_patterns:
            if re.search(pattern, url_lower):
                return True
        
        return False
    
    def _is_internal_ip(self, domain: str) -> bool:
        """Check if domain resolves to internal IP address."""
        try:
            # Resolve domain to IP
            ip_address = socket.gethostbyname(domain)
            
            # Check if IP is in internal ranges
            for internal_range in self.internal_ranges:
                if ipaddress.ip_address(ip_address) in ipaddress.ip_network(internal_range):
                    return True
            
            return False
            
        except socket.gaierror:
            # Domain resolution failed
            return False
        except Exception as e:
            Logger.warning(f"Error checking internal IP for {domain}: {str(e)}")
            return False
    
    def detect_ssrf_attempt(self, url: str) -> bool:
        """
        Detect potential SSRF attempts.
        
        Args:
            url (str): URL to check
            
        Returns:
            bool: True if SSRF attempt detected, False otherwise
        """
        url_lower = url.lower()
        
        # Check for common SSRF indicators
        ssrf_indicators = [
            # Internal services
            "localhost", "127.0.0.1", "0.0.0.0", "::1",
            # Internal network
            "10.", "172.", "192.168.",
            # Cloud metadata services
            "169.254.169.254",  # AWS metadata
            "metadata.google.internal",  # GCP metadata
            "169.254.169.254/latest/meta-data",  # AWS metadata path
            # File protocols
            "file://", "ftp://", "gopher://", "dict://",
            # Internal services
            "redis://", "mongodb://", "mysql://", "postgresql://",
            # Common internal ports
            ":22", ":21", ":23", ":25", ":53", ":1433", ":3306", ":5432", ":6379"
        ]
        
        for indicator in ssrf_indicators:
            if indicator in url_lower:
                Logger.warning(f"SSRF attempt detected: {url}")
                return True
        
        # Check for port scanning patterns
        port_scan_patterns = [
            r":\d{1,5}$",  # Port numbers
            r"\.\d{1,5}$",  # IP with port
        ]
        
        for pattern in port_scan_patterns:
            if re.search(pattern, url_lower):
                # Additional validation for port scanning
                if self._is_port_scanning_attempt(url):
                    return True
        
        return False
    
    def _is_port_scanning_attempt(self, url: str) -> bool:
        """Check if URL is attempting port scanning."""
        try:
            parsed_url = urlparse(url)
            port = parsed_url.port
            
            if port:
                # Check if port is commonly scanned
                commonly_scanned_ports = [22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 3306, 5432, 6379, 8080, 8443]
                if port not in commonly_scanned_ports:
                    return True
                
                # Check for multiple port attempts in short time
                # This would require tracking in a real implementation
                return False
            
            return False
            
        except Exception:
            return False
    
    def filter_request(self, request_data: dict) -> dict:
        """
        Filter and sanitize request data for SSRF protection.
        
        Args:
            request_data (dict): Request data to filter
            
        Returns:
            dict: Filtered request data
        """
        filtered_data = {}
        
        for key, value in request_data.items():
            if isinstance(value, str):
                # Validate URLs in string values
                if self._looks_like_url(value):
                    validation_result = self.validate_url(value)
                    if validation_result['valid']:
                        filtered_data[key] = value
                    else:
                        Logger.warning(f"URL filtered from request: {value}")
                        filtered_data[key] = "[URL_FILTERED]"
                else:
                    filtered_data[key] = value
            elif isinstance(value, dict):
                # Recursively filter nested dictionaries
                filtered_data[key] = self.filter_request(value)
            elif isinstance(value, list):
                # Filter list items
                filtered_data[key] = [
                    self.filter_request(item) if isinstance(item, dict)
                    else (item if not self._looks_like_url(str(item)) else "[URL_FILTERED]")
                    for item in value
                ]
            else:
                filtered_data[key] = value
        
        return filtered_data
    
    def _looks_like_url(self, value: str) -> bool:
        """Check if a string looks like a URL."""
        url_patterns = [
            r'^https?://',
            r'^ftp://',
            r'^file://',
            r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',  # Domain pattern
            r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP pattern
        ]
        
        for pattern in url_patterns:
            if re.match(pattern, value):
                return True
        
        return False
    
    def add_allowed_domain(self, domain: str) -> bool:
        """
        Add domain to allowlist.
        
        Args:
            domain (str): Domain to add
            
        Returns:
            bool: True if added successfully, False otherwise
        """
        if domain not in self.allowed_domains:
            self.allowed_domains.append(domain)
            self._save_config()
            Logger.info(f"Added domain to SSRF allowlist: {domain}")
            return True
        return False
    
    def remove_allowed_domain(self, domain: str) -> bool:
        """
        Remove domain from allowlist.
        
        Args:
            domain (str): Domain to remove
            
        Returns:
            bool: True if removed successfully, False otherwise
        """
        if domain in self.allowed_domains:
            self.allowed_domains.remove(domain)
            self._save_config()
            Logger.info(f"Removed domain from SSRF allowlist: {domain}")
            return True
        return False
    
    def get_ssrf_statistics(self) -> dict:
        """Get SSRF protection statistics."""
        stats = {
            'allowed_domains': len(self.allowed_domains),
            'allowed_protocols': len(self.allowed_protocols),
            'allowed_ports': len(self.allowed_ports),
            'internal_ranges': len(self.internal_ranges),
            'suspicious_patterns': len(self.suspicious_patterns),
            'configuration_file': os.path.exists(self.config_file)
        }
        
        return stats
    
    def test_url_validation(self, test_urls: List[str]) -> dict:
        """
        Test URL validation with sample URLs.
        
        Args:
            test_urls (List[str]): List of URLs to test
            
        Returns:
            dict: Test results
        """
        results = {
            'total_tested': len(test_urls),
            'valid_urls': 0,
            'invalid_urls': 0,
            'ssrf_attempts_detected': 0,
            'results': []
        }
        
        for url in test_urls:
            validation_result = self.validate_url(url)
            ssrf_detected = self.detect_ssrf_attempt(url)
            
            result = {
                'url': url,
                'valid': validation_result['valid'],
                'ssrf_detected': ssrf_detected,
                'errors': validation_result['errors'],
                'warnings': validation_result['warnings']
            }
            
            results['results'].append(result)
            
            if validation_result['valid']:
                results['valid_urls'] += 1
            else:
                results['invalid_urls'] += 1
            
            if ssrf_detected:
                results['ssrf_attempts_detected'] += 1
        
        return results

# Global SSRF protection instance
ssrf_protection = SSRFProtection() 