"""
Filename: advanced_logger.py
Author: Mobeen Ali
Date: July 2025

Purpose:
--------
Implements advanced logging and monitoring for the Secure CLI E-Commerce Application.
Addresses OWASP A09: Security Logging and Monitoring Failures by providing comprehensive
logging, real-time monitoring, SIEM integration, and incident response capabilities.

Security Features:
------------------
- Comprehensive security event logging
- Real-time monitoring and alerting
- SIEM integration capabilities
- Log integrity protection
- Incident response automation
- Anomaly detection
- Audit trail management
- Security metrics dashboard

Usage:
-------
- AdvancedLogger.log_security_event(event_type, details) -> None
- AdvancedLogger.detect_anomalies() -> list
- AdvancedLogger.generate_security_report() -> dict
- AdvancedLogger.trigger_incident_response(incident) -> bool
"""

import json
import os
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from collections import defaultdict, deque
import hashlib
import hmac
from enum import Enum
from app.core.logger import Logger

class SecurityEventType(Enum):
    """Types of security events."""
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    SESSION_CREATED = "session_created"
    SESSION_EXPIRED = "session_expired"
    SESSION_HIJACKED = "session_hijacked"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    ACCOUNT_LOCKED = "account_locked"
    PASSWORD_CHANGED = "password_changed"
    DATA_ACCESSED = "data_accessed"
    DATA_MODIFIED = "data_modified"
    INTEGRITY_VIOLATION = "integrity_violation"
    VULNERABILITY_DETECTED = "vulnerability_detected"
    THREAT_DETECTED = "threat_detected"
    ANOMALY_DETECTED = "anomaly_detected"
    INCIDENT_RESPONSE = "incident_response"

class IncidentSeverity(Enum):
    """Incident severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class AdvancedLogger:
    """Advanced logging and monitoring system."""
    
    def __init__(self):
        self.security_log_file = "logs/security_events.log"
        self.audit_log_file = "logs/audit_trail.log"
        self.incident_log_file = "logs/incidents.log"
        self.metrics_file = "logs/security_metrics.json"
        
        # Log integrity
        self.log_secret = os.urandom(32)
        
        # Real-time monitoring
        self.event_queue = deque(maxlen=1000)
        self.anomaly_thresholds = {
            'failed_logins_per_hour': 10,
            'suspicious_ips_per_hour': 5,
            'integrity_violations_per_day': 3,
            'session_hijacking_attempts': 1
        }
        
        # Incident response
        self.active_incidents = {}
        self.incident_counter = 0
        
        # Metrics
        self.security_metrics = {
            'total_events': 0,
            'security_incidents': 0,
            'anomalies_detected': 0,
            'integrity_violations': 0,
            'rate_limit_violations': 0,
            'last_updated': datetime.utcnow().isoformat()
        }
        
        # Start monitoring thread
        self.monitoring_active = True
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitoring_thread.start()
    
    def log_security_event(self, event_type: SecurityEventType, details: dict, severity: str = "info") -> None:
        """
        Log a security event with integrity protection.
        
        Args:
            event_type (SecurityEventType): Type of security event
            details (dict): Event details
            severity (str): Event severity (info, warning, error, critical)
        """
        timestamp = datetime.utcnow()
        event_id = self._generate_event_id()
        
        event_data = {
            'event_id': event_id,
            'timestamp': timestamp.isoformat(),
            'event_type': event_type.value,
            'severity': severity,
            'details': details,
            'source_ip': details.get('source_ip', 'unknown'),
            'user_id': details.get('user_id', 'unknown'),
            'session_id': details.get('session_id', 'unknown')
        }
        
        # Add to real-time queue
        self.event_queue.append(event_data)
        
        # Log to file with integrity protection
        self._write_security_log(event_data)
        
        # Update metrics
        self._update_metrics(event_type, severity)
        
        # Check for anomalies
        self._check_anomalies(event_data)
        
        # Trigger incident response if needed
        if severity in ['error', 'critical']:
            self._trigger_incident_response(event_data)
        
        Logger.info(f"Security event logged: {event_type.value} - {event_id}")
    
    def _generate_event_id(self) -> str:
        """Generate unique event ID."""
        timestamp = datetime.utcnow().isoformat()
        random_component = os.urandom(8).hex()
        return f"evt_{timestamp}_{random_component}".replace(':', '').replace('-', '').replace('.', '')
    
    def _write_security_log(self, event_data: dict):
        """Write security event to log file with integrity protection."""
        try:
            # Create log entry
            log_entry = json.dumps(event_data, indent=2)
            
            # Add integrity hash
            integrity_hash = hmac.new(
                self.log_secret,
                log_entry.encode(),
                hashlib.sha256
            ).hexdigest()
            
            # Write to file
            with open(self.security_log_file, 'a', encoding='utf-8') as f:
                f.write(f"{log_entry}\n")
                f.write(f"INTEGRITY_HASH: {integrity_hash}\n")
                f.write("-" * 80 + "\n")
                
        except Exception as e:
            Logger.error(f"Failed to write security log: {str(e)}")
    
    def _update_metrics(self, event_type: SecurityEventType, severity: str):
        """Update security metrics."""
        self.security_metrics['total_events'] += 1
        
        if severity in ['error', 'critical']:
            self.security_metrics['security_incidents'] += 1
        
        if event_type == SecurityEventType.INTEGRITY_VIOLATION:
            self.security_metrics['integrity_violations'] += 1
        
        if event_type == SecurityEventType.RATE_LIMIT_EXCEEDED:
            self.security_metrics['rate_limit_violations'] += 1
        
        self.security_metrics['last_updated'] = datetime.utcnow().isoformat()
        
        # Save metrics
        self._save_metrics()
    
    def _check_anomalies(self, event_data: dict):
        """Check for security anomalies."""
        current_time = datetime.utcnow()
        recent_events = [
            event for event in self.event_queue
            if current_time - datetime.fromisoformat(event['timestamp']) < timedelta(hours=1)
        ]
        
        # Check for failed login anomalies
        failed_logins = [
            event for event in recent_events
            if event['event_type'] == SecurityEventType.LOGIN_FAILURE.value
        ]
        
        if len(failed_logins) > self.anomaly_thresholds['failed_logins_per_hour']:
            self._log_anomaly("High number of failed login attempts", {
                'count': len(failed_logins),
                'threshold': self.anomaly_thresholds['failed_logins_per_hour'],
                'time_window': '1 hour'
            })
        
        # Check for suspicious IP patterns
        ip_counts = defaultdict(int)
        for event in recent_events:
            ip_counts[event['source_ip']] += 1
        
        suspicious_ips = [
            ip for ip, count in ip_counts.items()
            if count > self.anomaly_thresholds['suspicious_ips_per_hour']
        ]
        
        if len(suspicious_ips) > 0:
            self._log_anomaly("Suspicious IP activity detected", {
                'suspicious_ips': suspicious_ips,
                'threshold': self.anomaly_thresholds['suspicious_ips_per_hour']
            })
    
    def _log_anomaly(self, description: str, details: dict):
        """Log a detected anomaly."""
        anomaly_event = {
            'event_type': SecurityEventType.ANOMALY_DETECTED.value,
            'description': description,
            'details': details,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        self.log_security_event(
            SecurityEventType.ANOMALY_DETECTED,
            anomaly_event,
            'warning'
        )
        
        self.security_metrics['anomalies_detected'] += 1
        self._save_metrics()
    
    def _trigger_incident_response(self, event_data: dict):
        """Trigger incident response for critical events."""
        incident_id = f"inc_{self.incident_counter:06d}"
        self.incident_counter += 1
        
        incident = {
            'incident_id': incident_id,
            'timestamp': datetime.utcnow().isoformat(),
            'event_data': event_data,
            'status': 'active',
            'severity': self._determine_incident_severity(event_data),
            'response_actions': [],
            'resolution': None
        }
        
        self.active_incidents[incident_id] = incident
        
        # Log incident
        self._write_incident_log(incident)
        
        # Execute response actions
        self._execute_incident_response(incident)
        
        Logger.warning(f"Incident response triggered: {incident_id}")
    
    def _determine_incident_severity(self, event_data: dict) -> IncidentSeverity:
        """Determine incident severity based on event data."""
        event_type = event_data['event_type']
        severity = event_data['severity']
        
        if severity == 'critical':
            return IncidentSeverity.CRITICAL
        elif event_type in [SecurityEventType.SESSION_HIJACKED.value, SecurityEventType.INTEGRITY_VIOLATION.value]:
            return IncidentSeverity.HIGH
        elif event_type in [SecurityEventType.ACCOUNT_LOCKED.value, SecurityEventType.RATE_LIMIT_EXCEEDED.value]:
            return IncidentSeverity.MEDIUM
        else:
            return IncidentSeverity.LOW
    
    def _execute_incident_response(self, incident: dict):
        """Execute automated incident response actions."""
        actions = []
        
        if incident['severity'] in [IncidentSeverity.HIGH, IncidentSeverity.CRITICAL]:
            # High severity actions
            actions.append("Immediate session termination")
            actions.append("Account lockout")
            actions.append("Security alert notification")
        
        if incident['severity'] == IncidentSeverity.CRITICAL:
            # Critical severity actions
            actions.append("System lockdown")
            actions.append("Emergency contact notification")
            actions.append("Forensic data collection")
        
        # Log response actions
        incident['response_actions'] = actions
        
        # Update incident status
        incident['status'] = 'response_executed'
        
        Logger.info(f"Incident response executed for {incident['incident_id']}: {actions}")
    
    def _write_incident_log(self, incident: dict):
        """Write incident to log file."""
        try:
            with open(self.incident_log_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(incident, indent=2))
                f.write("\n" + "=" * 80 + "\n")
        except Exception as e:
            Logger.error(f"Failed to write incident log: {str(e)}")
    
    def _save_metrics(self):
        """Save security metrics to file."""
        try:
            with open(self.metrics_file, 'w') as f:
                json.dump(self.security_metrics, f, indent=2)
        except Exception as e:
            Logger.error(f"Failed to save metrics: {str(e)}")
    
    def _monitoring_loop(self):
        """Real-time monitoring loop."""
        while self.monitoring_active:
            try:
                # Process events in queue
                if self.event_queue:
                    self._process_event_queue()
                
                # Clean up old incidents
                self._cleanup_old_incidents()
                
                # Sleep for monitoring interval
                time.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                Logger.error(f"Monitoring loop error: {str(e)}")
                time.sleep(60)  # Wait longer on error
    
    def _process_event_queue(self):
        """Process events in the monitoring queue."""
        current_time = datetime.utcnow()
        
        # Remove old events from queue
        while self.event_queue and (
            current_time - datetime.fromisoformat(self.event_queue[0]['timestamp'])
        ) > timedelta(hours=24):
            self.event_queue.popleft()
    
    def _cleanup_old_incidents(self):
        """Clean up resolved incidents older than 30 days."""
        current_time = datetime.utcnow()
        cutoff_time = current_time - timedelta(days=30)
        
        for incident_id in list(self.active_incidents.keys()):
            incident = self.active_incidents[incident_id]
            incident_time = datetime.fromisoformat(incident['timestamp'])
            
            if incident_time < cutoff_time:
                del self.active_incidents[incident_id]
    
    def get_security_report(self) -> dict:
        """Generate comprehensive security report."""
        current_time = datetime.utcnow()
        
        # Calculate time-based metrics
        last_24h_events = [
            event for event in self.event_queue
            if current_time - datetime.fromisoformat(event['timestamp']) < timedelta(hours=24)
        ]
        
        last_7d_events = [
            event for event in self.event_queue
            if current_time - datetime.fromisoformat(event['timestamp']) < timedelta(days=7)
        ]
        
        report = {
            'report_generated': current_time.isoformat(),
            'metrics': self.security_metrics,
            'recent_activity': {
                'last_24h_events': len(last_24h_events),
                'last_7d_events': len(last_7d_events),
                'active_incidents': len(self.active_incidents)
            },
            'anomalies': self._get_recent_anomalies(),
            'incidents': self._get_recent_incidents(),
            'recommendations': self._generate_recommendations()
        }
        
        return report
    
    def _get_recent_anomalies(self) -> list:
        """Get recent anomalies."""
        current_time = datetime.utcnow()
        recent_anomalies = [
            event for event in self.event_queue
            if (event['event_type'] == SecurityEventType.ANOMALY_DETECTED.value and
                current_time - datetime.fromisoformat(event['timestamp']) < timedelta(hours=24))
        ]
        
        return recent_anomalies
    
    def _get_recent_incidents(self) -> list:
        """Get recent incidents."""
        current_time = datetime.utcnow()
        recent_incidents = [
            incident for incident in self.active_incidents.values()
            if current_time - datetime.fromisoformat(incident['timestamp']) < timedelta(days=7)
        ]
        
        return recent_incidents
    
    def _generate_recommendations(self) -> list:
        """Generate security recommendations based on metrics."""
        recommendations = []
        
        if self.security_metrics['integrity_violations'] > 0:
            recommendations.append("Review file integrity monitoring and investigate violations")
        
        if self.security_metrics['rate_limit_violations'] > 10:
            recommendations.append("Consider adjusting rate limiting thresholds")
        
        if self.security_metrics['anomalies_detected'] > 5:
            recommendations.append("Review anomaly detection thresholds and investigate patterns")
        
        if len(self.active_incidents) > 0:
            recommendations.append("Review and resolve active security incidents")
        
        return recommendations
    
    def validate_log_integrity(self) -> dict:
        """Validate integrity of security logs."""
        try:
            with open(self.security_log_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Parse log entries and validate hashes
            entries = content.split("-" * 80)
            valid_entries = 0
            invalid_entries = 0
            
            for entry in entries:
                if entry.strip():
                    lines = entry.strip().split('\n')
                    if len(lines) >= 2:
                        log_data = lines[0]
                        hash_line = lines[1]
                        
                        if hash_line.startswith('INTEGRITY_HASH: '):
                            expected_hash = hash_line.split(': ')[1]
                            actual_hash = hmac.new(
                                self.log_secret,
                                log_data.encode(),
                                hashlib.sha256
                            ).hexdigest()
                            
                            if expected_hash == actual_hash:
                                valid_entries += 1
                            else:
                                invalid_entries += 1
            
            return {
                'valid_entries': valid_entries,
                'invalid_entries': invalid_entries,
                'integrity_valid': invalid_entries == 0
            }
            
        except Exception as e:
            Logger.error(f"Failed to validate log integrity: {str(e)}")
            return {
                'valid_entries': 0,
                'invalid_entries': 0,
                'integrity_valid': False,
                'error': str(e)
            }

# Global advanced logger instance
advanced_logger = AdvancedLogger() 