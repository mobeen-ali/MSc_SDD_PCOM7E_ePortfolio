"""
Filename: threat_model.py
Author: Mobeen Ali
Date: July 2025

Purpose:
--------
Implements comprehensive threat modeling for the Secure CLI E-Commerce Application.
Addresses OWASP A04: Insecure Design by providing systematic threat analysis,
attack vector identification, and risk assessment.

Security Features:
------------------
- STRIDE threat modeling methodology
- Attack tree analysis
- Risk assessment and scoring
- Threat categorization and prioritization
- Mitigation strategy documentation
- Continuous threat monitoring

Usage:
-------
- ThreatModel.analyze_threats() -> dict
- ThreatModel.assess_risk(threat_id) -> float
- ThreatModel.get_mitigations(threat_id) -> list
- ThreatModel.update_threat_status(threat_id, status) -> bool
"""

import json
import os
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional
from app.core.logger import Logger

class ThreatCategory(Enum):
    """Threat categories based on STRIDE methodology."""
    SPOOFING = "Spoofing"
    TAMPERING = "Tampering"
    REPUDIATION = "Repudiation"
    INFORMATION_DISCLOSURE = "Information Disclosure"
    DENIAL_OF_SERVICE = "Denial of Service"
    ELEVATION_OF_PRIVILEGE = "Elevation of Privilege"

class RiskLevel(Enum):
    """Risk levels for threat assessment."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Informational"

class ThreatStatus(Enum):
    """Status of threat mitigation."""
    OPEN = "Open"
    IN_PROGRESS = "In Progress"
    MITIGATED = "Mitigated"
    ACCEPTED = "Accepted"
    FALSE_POSITIVE = "False Positive"

class ThreatModel:
    """
    Comprehensive threat modeling system for the e-commerce application.
    """
    
    def __init__(self):
        """Initialize threat model with predefined threats."""
        self.threats_file = "data/threat_model.json"
        self.threats = self._load_threats()
        self._initialize_default_threats()
    
    def _load_threats(self) -> Dict:
        """Load threats from persistent storage."""
        if not os.path.exists(self.threats_file):
            return {}
        
        try:
            with open(self.threats_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            Logger.error(f"Failed to load threat model: {str(e)}")
            return {}
    
    def _save_threats(self):
        """Save threats to persistent storage."""
        try:
            with open(self.threats_file, 'w') as f:
                json.dump(self.threats, f, indent=2)
        except Exception as e:
            Logger.error(f"Failed to save threat model: {str(e)}")
    
    def _initialize_default_threats(self):
        """Initialize default threat model based on OWASP Top 10 and STRIDE."""
        if not self.threats:
            self.threats = {
                "A01_BROKEN_ACCESS_CONTROL": {
                    "id": "A01_BROKEN_ACCESS_CONTROL",
                    "title": "Broken Access Control",
                    "description": "Unauthorized access to resources due to missing or improper access controls",
                    "category": ThreatCategory.ELEVATION_OF_PRIVILEGE.value,
                    "risk_level": RiskLevel.HIGH.value,
                    "status": ThreatStatus.MITIGATED.value,
                    "attack_vectors": [
                        "Session hijacking",
                        "Privilege escalation",
                        "Insecure direct object references",
                        "Missing authorization checks"
                    ],
                    "mitigations": [
                        "Session management with JWT tokens",
                        "Role-based access control",
                        "Proper session timeout",
                        "Input validation and sanitization"
                    ],
                    "detection_methods": [
                        "Session monitoring",
                        "Access log analysis",
                        "Anomaly detection"
                    ],
                    "created_at": datetime.utcnow().isoformat(),
                    "last_updated": datetime.utcnow().isoformat()
                },
                "A02_CRYPTOGRAPHIC_FAILURES": {
                    "id": "A02_CRYPTOGRAPHIC_FAILURES",
                    "title": "Cryptographic Failures",
                    "description": "Weak or missing cryptographic controls leading to data exposure",
                    "category": ThreatCategory.INFORMATION_DISCLOSURE.value,
                    "risk_level": RiskLevel.CRITICAL.value,
                    "status": ThreatStatus.MITIGATED.value,
                    "attack_vectors": [
                        "Weak encryption algorithms",
                        "Insecure key management",
                        "Missing key rotation",
                        "Insecure transmission"
                    ],
                    "mitigations": [
                        "Strong encryption (AES-256, Fernet)",
                        "Key rotation and management",
                        "Secure key storage",
                        "TLS for data transmission"
                    ],
                    "detection_methods": [
                        "Cryptographic algorithm validation",
                        "Key integrity checks",
                        "Encryption strength testing"
                    ],
                    "created_at": datetime.utcnow().isoformat(),
                    "last_updated": datetime.utcnow().isoformat()
                },
                "A03_INJECTION": {
                    "id": "A03_INJECTION",
                    "title": "Injection Attacks",
                    "description": "Malicious input injection leading to code execution or data manipulation",
                    "category": ThreatCategory.TAMPERING.value,
                    "risk_level": RiskLevel.HIGH.value,
                    "status": ThreatStatus.MITIGATED.value,
                    "attack_vectors": [
                        "SQL injection",
                        "Command injection",
                        "LDAP injection",
                        "NoSQL injection"
                    ],
                    "mitigations": [
                        "Input validation and sanitization",
                        "Parameterized queries",
                        "CLI-bound input handling",
                        "Output encoding"
                    ],
                    "detection_methods": [
                        "Input validation testing",
                        "Anomaly detection",
                        "Pattern matching"
                    ],
                    "created_at": datetime.utcnow().isoformat(),
                    "last_updated": datetime.utcnow().isoformat()
                },
                "A04_INSECURE_DESIGN": {
                    "id": "A04_INSECURE_DESIGN",
                    "title": "Insecure Design",
                    "description": "Flaws in design and architecture leading to security vulnerabilities",
                    "category": ThreatCategory.ELEVATION_OF_PRIVILEGE.value,
                    "risk_level": RiskLevel.HIGH.value,
                    "status": ThreatStatus.IN_PROGRESS.value,
                    "attack_vectors": [
                        "Missing threat modeling",
                        "Insecure architecture",
                        "Poor security requirements",
                        "Lack of security controls"
                    ],
                    "mitigations": [
                        "Comprehensive threat modeling",
                        "Secure design principles",
                        "Security architecture review",
                        "Security requirements definition"
                    ],
                    "detection_methods": [
                        "Architecture review",
                        "Threat modeling analysis",
                        "Security assessment"
                    ],
                    "created_at": datetime.utcnow().isoformat(),
                    "last_updated": datetime.utcnow().isoformat()
                },
                "A05_SECURITY_MISCONFIGURATION": {
                    "id": "A05_SECURITY_MISCONFIGURATION",
                    "title": "Security Misconfiguration",
                    "description": "Insecure default configurations and missing security settings",
                    "category": ThreatCategory.INFORMATION_DISCLOSURE.value,
                    "risk_level": RiskLevel.MEDIUM.value,
                    "status": ThreatStatus.MITIGATED.value,
                    "attack_vectors": [
                        "Default credentials",
                        "Unnecessary features enabled",
                        "Insecure default settings",
                        "Missing security headers"
                    ],
                    "mitigations": [
                        "Secure default configurations",
                        "Security toggle controls",
                        "Configuration validation",
                        "Regular security audits"
                    ],
                    "detection_methods": [
                        "Configuration scanning",
                        "Security assessment",
                        "Automated testing"
                    ],
                    "created_at": datetime.utcnow().isoformat(),
                    "last_updated": datetime.utcnow().isoformat()
                },
                "A06_VULNERABLE_COMPONENTS": {
                    "id": "A06_VULNERABLE_COMPONENTS",
                    "title": "Vulnerable and Outdated Components",
                    "description": "Use of components with known vulnerabilities",
                    "category": ThreatCategory.ELEVATION_OF_PRIVILEGE.value,
                    "risk_level": RiskLevel.MEDIUM.value,
                    "status": ThreatStatus.OPEN.value,
                    "attack_vectors": [
                        "Outdated dependencies",
                        "Known vulnerabilities",
                        "Unpatched components",
                        "Insecure third-party code"
                    ],
                    "mitigations": [
                        "Dependency vulnerability scanning",
                        "Regular updates and patches",
                        "Component inventory management",
                        "Security testing of components"
                    ],
                    "detection_methods": [
                        "Automated vulnerability scanning",
                        "Dependency analysis",
                        "Security advisories monitoring"
                    ],
                    "created_at": datetime.utcnow().isoformat(),
                    "last_updated": datetime.utcnow().isoformat()
                },
                "A07_AUTHENTICATION_FAILURES": {
                    "id": "A07_AUTHENTICATION_FAILURES",
                    "title": "Identification and Authentication Failures",
                    "description": "Weak authentication mechanisms leading to unauthorized access",
                    "category": ThreatCategory.SPOOFING.value,
                    "risk_level": RiskLevel.HIGH.value,
                    "status": ThreatStatus.MITIGATED.value,
                    "attack_vectors": [
                        "Weak passwords",
                        "Brute force attacks",
                        "Session fixation",
                        "Credential stuffing"
                    ],
                    "mitigations": [
                        "Strong password policies",
                        "Multi-factor authentication",
                        "Account lockout mechanisms",
                        "Secure session management"
                    ],
                    "detection_methods": [
                        "Failed login monitoring",
                        "Anomaly detection",
                        "Account lockout tracking"
                    ],
                    "created_at": datetime.utcnow().isoformat(),
                    "last_updated": datetime.utcnow().isoformat()
                },
                "A08_SOFTWARE_INTEGRITY_FAILURES": {
                    "id": "A08_SOFTWARE_INTEGRITY_FAILURES",
                    "title": "Software and Data Integrity Failures",
                    "description": "Unauthorized modification of software or data",
                    "category": ThreatCategory.TAMPERING.value,
                    "risk_level": RiskLevel.MEDIUM.value,
                    "status": ThreatStatus.OPEN.value,
                    "attack_vectors": [
                        "Code injection",
                        "Data tampering",
                        "Supply chain attacks",
                        "Unauthorized modifications"
                    ],
                    "mitigations": [
                        "Code integrity checks",
                        "Digital signatures",
                        "Secure update mechanisms",
                        "Data integrity validation"
                    ],
                    "detection_methods": [
                        "Integrity monitoring",
                        "Checksum validation",
                        "Anomaly detection"
                    ],
                    "created_at": datetime.utcnow().isoformat(),
                    "last_updated": datetime.utcnow().isoformat()
                },
                "A09_LOGGING_FAILURES": {
                    "id": "A09_LOGGING_FAILURES",
                    "title": "Security Logging and Monitoring Failures",
                    "description": "Insufficient logging and monitoring leading to undetected attacks",
                    "category": ThreatCategory.REPUDIATION.value,
                    "risk_level": RiskLevel.MEDIUM.value,
                    "status": ThreatStatus.MITIGATED.value,
                    "attack_vectors": [
                        "Log tampering",
                        "Insufficient monitoring",
                        "Delayed incident response",
                        "Missing audit trails"
                    ],
                    "mitigations": [
                        "Comprehensive logging",
                        "Real-time monitoring",
                        "Log integrity protection",
                        "Incident response procedures"
                    ],
                    "detection_methods": [
                        "Log analysis",
                        "SIEM integration",
                        "Anomaly detection"
                    ],
                    "created_at": datetime.utcnow().isoformat(),
                    "last_updated": datetime.utcnow().isoformat()
                },
                "A10_SSRF": {
                    "id": "A10_SSRF",
                    "title": "Server-Side Request Forgery",
                    "description": "Unauthorized server requests to internal or external resources",
                    "category": ThreatCategory.INFORMATION_DISCLOSURE.value,
                    "risk_level": RiskLevel.MEDIUM.value,
                    "status": ThreatStatus.OPEN.value,
                    "attack_vectors": [
                        "URL manipulation",
                        "Internal resource access",
                        "External service abuse",
                        "Network reconnaissance"
                    ],
                    "mitigations": [
                        "Input validation",
                        "URL allowlisting",
                        "Network segmentation",
                        "Request filtering"
                    ],
                    "detection_methods": [
                        "Request monitoring",
                        "Anomaly detection",
                        "Network traffic analysis"
                    ],
                    "created_at": datetime.utcnow().isoformat(),
                    "last_updated": datetime.utcnow().isoformat()
                }
            }
            self._save_threats()
    
    def analyze_threats(self) -> Dict:
        """
        Perform comprehensive threat analysis.
        
        Returns:
            Dict: Complete threat analysis report
        """
        analysis = {
            "summary": {
                "total_threats": len(self.threats),
                "critical_threats": 0,
                "high_threats": 0,
                "medium_threats": 0,
                "low_threats": 0,
                "mitigated_threats": 0,
                "open_threats": 0
            },
            "threats_by_category": {},
            "threats_by_risk": {},
            "threats_by_status": {},
            "recommendations": []
        }
        
        # Analyze threats
        for threat_id, threat_data in self.threats.items():
            risk_level = threat_data["risk_level"]
            status = threat_data["status"]
            category = threat_data["category"]
            
            # Count by risk level
            if risk_level not in analysis["threats_by_risk"]:
                analysis["threats_by_risk"][risk_level] = 0
            analysis["threats_by_risk"][risk_level] += 1
            
            # Count by status
            if status not in analysis["threats_by_status"]:
                analysis["threats_by_status"][status] = 0
            analysis["threats_by_status"][status] += 1
            
            # Count by category
            if category not in analysis["threats_by_category"]:
                analysis["threats_by_category"][category] = 0
            analysis["threats_by_category"][category] += 1
            
            # Update summary counts
            if risk_level == RiskLevel.CRITICAL.value:
                analysis["summary"]["critical_threats"] += 1
            elif risk_level == RiskLevel.HIGH.value:
                analysis["summary"]["high_threats"] += 1
            elif risk_level == RiskLevel.MEDIUM.value:
                analysis["summary"]["medium_threats"] += 1
            elif risk_level == RiskLevel.LOW.value:
                analysis["summary"]["low_threats"] += 1
            
            if status == ThreatStatus.MITIGATED.value:
                analysis["summary"]["mitigated_threats"] += 1
            elif status in [ThreatStatus.OPEN.value, ThreatStatus.IN_PROGRESS.value]:
                analysis["summary"]["open_threats"] += 1
        
        # Generate recommendations
        analysis["recommendations"] = self._generate_recommendations()
        
        return analysis
    
    def assess_risk(self, threat_id: str) -> float:
        """
        Assess risk score for a specific threat.
        
        Args:
            threat_id (str): Threat identifier
            
        Returns:
            float: Risk score (0.0 to 1.0)
        """
        if threat_id not in self.threats:
            return 0.0
        
        threat = self.threats[threat_id]
        
        # Risk scoring factors
        risk_factors = {
            RiskLevel.CRITICAL.value: 1.0,
            RiskLevel.HIGH.value: 0.8,
            RiskLevel.MEDIUM.value: 0.5,
            RiskLevel.LOW.value: 0.2,
            RiskLevel.INFO.value: 0.1
        }
        
        base_risk = risk_factors.get(threat["risk_level"], 0.5)
        
        # Adjust based on status
        status_factors = {
            ThreatStatus.OPEN.value: 1.0,
            ThreatStatus.IN_PROGRESS.value: 0.7,
            ThreatStatus.MITIGATED.value: 0.1,
            ThreatStatus.ACCEPTED.value: 0.3,
            ThreatStatus.FALSE_POSITIVE.value: 0.0
        }
        
        status_factor = status_factors.get(threat["status"], 1.0)
        
        return base_risk * status_factor
    
    def get_mitigations(self, threat_id: str) -> List[str]:
        """
        Get mitigation strategies for a specific threat.
        
        Args:
            threat_id (str): Threat identifier
            
        Returns:
            List[str]: List of mitigation strategies
        """
        if threat_id not in self.threats:
            return []
        
        return self.threats[threat_id].get("mitigations", [])
    
    def update_threat_status(self, threat_id: str, status: str) -> bool:
        """
        Update the status of a threat.
        
        Args:
            threat_id (str): Threat identifier
            status (str): New status
            
        Returns:
            bool: True if update was successful
        """
        if threat_id not in self.threats:
            return False
        
        self.threats[threat_id]["status"] = status
        self.threats[threat_id]["last_updated"] = datetime.utcnow().isoformat()
        self._save_threats()
        
        Logger.info(f"Updated threat {threat_id} status to {status}")
        return True
    
    def add_threat(self, threat_data: Dict) -> str:
        """
        Add a new threat to the model.
        
        Args:
            threat_data (Dict): Threat information
            
        Returns:
            str: Threat ID
        """
        threat_id = threat_data.get("id", f"THREAT_{len(self.threats) + 1}")
        threat_data["created_at"] = datetime.utcnow().isoformat()
        threat_data["last_updated"] = datetime.utcnow().isoformat()
        
        self.threats[threat_id] = threat_data
        self._save_threats()
        
        Logger.info(f"Added new threat: {threat_id}")
        return threat_id
    
    def _generate_recommendations(self) -> List[str]:
        """
        Generate security recommendations based on threat analysis.
        
        Returns:
            List[str]: List of recommendations
        """
        recommendations = []
        
        # Analyze open high/critical threats
        open_critical_threats = [
            t for t in self.threats.values()
            if t["status"] in [ThreatStatus.OPEN.value, ThreatStatus.IN_PROGRESS.value]
            and t["risk_level"] in [RiskLevel.CRITICAL.value, RiskLevel.HIGH.value]
        ]
        
        if open_critical_threats:
            recommendations.append(
                f"Prioritize mitigation of {len(open_critical_threats)} open critical/high risk threats"
            )
        
        # Check for missing mitigations
        threats_without_mitigations = [
            t for t in self.threats.values()
            if not t.get("mitigations")
        ]
        
        if threats_without_mitigations:
            recommendations.append(
                f"Define mitigation strategies for {len(threats_without_mitigations)} threats"
            )
        
        # Check for outdated threats
        current_time = datetime.utcnow()
        outdated_threats = []
        for threat in self.threats.values():
            last_updated = datetime.fromisoformat(threat["last_updated"])
            if (current_time - last_updated).days > 90:
                outdated_threats.append(threat["id"])
        
        if outdated_threats:
            recommendations.append(
                f"Review and update {len(outdated_threats)} outdated threat assessments"
            )
        
        return recommendations
    
    def export_threat_model(self, format: str = "json") -> str:
        """
        Export threat model in specified format.
        
        Args:
            format (str): Export format (json, csv, html)
            
        Returns:
            str: Exported threat model
        """
        if format == "json":
            return json.dumps(self.threats, indent=2)
        elif format == "csv":
            # Implement CSV export
            return "CSV export not implemented"
        elif format == "html":
            # Implement HTML export
            return "HTML export not implemented"
        else:
            raise ValueError(f"Unsupported format: {format}")

# Global threat model instance
threat_model = ThreatModel() 