# Project Structure

## 📁 Main Application

```
ecommerce_cli_SSD_Project_updated/
├── app/                          # Main application code
│   ├── core/                     # Core security and business logic
│   │   ├── auth.py              # Authentication and user management
│   │   ├── session.py           # Session management (OWASP A01)
│   │   ├── crypto_manager.py    # Cryptographic key management (OWASP A02)
│   │   ├── threat_model.py      # Threat modeling (OWASP A04)
│   │   ├── vulnerability_scanner.py # Vulnerability scanning (OWASP A06)
│   │   ├── rate_limiter.py      # Rate limiting and account lockout (OWASP A07)
│   │   ├── integrity_manager.py # Data integrity (OWASP A08)
│   │   ├── advanced_logger.py   # Security logging (OWASP A09)
│   │   ├── ssrf_protection.py   # SSRF protection (OWASP A10)
│   │   ├── storage.py           # Secure data storage
│   │   └── logger.py            # Basic logging
│   ├── models/                   # Data models
│   │   ├── user.py              # User model with OTP
│   │   ├── product.py           # Product model
│   │   ├── cart.py              # Shopping cart model
│   │   └── order.py             # Order management model
│   └── cli.py                   # Command-line interface
├── tests/                        # Comprehensive test suite
│   ├── test_security_features.py # OWASP A01-A06 security tests
│   └── reports/                  # Test reports and screenshots
├── demo_scripts/                 # Demonstration scripts
│   ├── demo_otp.py              # OTP demonstration
│   ├── video_demo.py            # Complete video demo script
│   └── README.md                # Demo scripts documentation
├── docs/                         # Project documentation
├── logs/                         # Application logs
├── tools/                        # Security tools and utilities
└── run.py                        # Main application entry point
```

## 🔐 Security Features (OWASP A01-A10)

### A01 - Session Management
- JWT-based session tokens
- Session timeout and automatic logout
- Secure session storage with encryption

### A02 - Cryptographic Failures
- Cryptographic key rotation
- Secure key management
- Encryption/decryption with fallback

### A04 - Insecure Design
- Comprehensive threat modeling
- Risk assessment and mitigation
- Security architecture validation

### A06 - Vulnerable Components
- Dependency vulnerability scanning
- Security advisory checking
- Component update management

### A07 - Authentication Failures
- Rate limiting and account lockout
- Advanced password policy enforcement
- Failed attempt tracking

### A08 - Software Integrity
- Data integrity validation
- Checksum verification
- Digital signature support

### A09 - Security Logging
- Advanced security event logging
- SIEM integration
- Anomaly detection

### A10 - SSRF
- URL validation and filtering
- Network segmentation
- SSRF protection mechanisms

## 🛒 E-Commerce Features

- User registration and authentication
- Product catalog management
- Shopping cart functionality
- Order processing and checkout
- Payment simulation with fraud detection
- Inventory management

## 🧪 Testing

- Comprehensive security testing
- Automated test suite
- Vulnerability scanning
- Security audit reports

## 📊 Documentation

- Complete implementation summaries
- Security feature documentation
- OWASP compliance reports
- Video demonstration scripts 