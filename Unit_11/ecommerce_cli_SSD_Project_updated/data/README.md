# Data Directory

This folder contains all application data files.

## Files

### User and Session Data
- `users.json` - User database with encrypted credentials
- `sessions.json` - Active session storage
- `current_session.txt` - Current user session token
- `rate_limits.json` - Rate limiting and account lockout data
- `password_history.json` - Password history for policy enforcement

### Product and E-Commerce Data
- `products.json` - Product catalog and inventory

### Security and Configuration Data
- `crypto_keys.json` - Cryptographic key management
- `file_monitoring.json` - File integrity monitoring data
- `threat_model.json` - Threat modeling and risk assessment data
- `vulnerability_report.json` - Vulnerability scanning results
- `component_inventory.json` - Software component inventory

## Purpose

All application data is stored here in a structured format. The data files are used by the application for:
- User authentication and session management
- Product catalog and inventory management
- Security monitoring and threat assessment
- Vulnerability tracking and reporting

## Security

- User data is encrypted at rest
- Session tokens are securely managed
- Cryptographic keys are properly stored
- All data follows security best practices 