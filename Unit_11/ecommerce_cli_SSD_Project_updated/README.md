
# Secure CLI E-Commerce Application

A secure command-line e-commerce application implementing OWASP A01-A10 security practices.

## Overview

This project demonstrates secure software development practices through a functional e-commerce system. The application includes user authentication, product management, shopping cart functionality, and comprehensive security features.

## Features

### E-Commerce Functionality
- User registration and authentication with OTP
- Product catalog management
- Shopping cart and checkout process
- Order processing and inventory management

### Security Features (OWASP A01-A10)
- **A01**: Session management with JWT tokens
- **A02**: Cryptographic key rotation and secure storage
- **A03**: Input validation and injection prevention
- **A04**: Comprehensive threat modeling
- **A05**: Security misconfiguration prevention
- **A06**: Dependency vulnerability scanning
- **A07**: Rate limiting and account lockout
- **A08**: Data integrity validation
- **A09**: Advanced security logging
- **A10**: SSRF protection mechanisms

## Installation

### Prerequisites
- Python 3.8+
- Virtual environment

### Setup
```bash
# Clone the repository
git clone https://github.com/mobeen-ali/MSc_SDD_PCOM7E_ePortfolio
cd Unit_11/ecommerce_cli_SSD_Project_updated

# Create virtual environment
python -m venv .venv

# Activate virtual environment
# On Windows:
.venv\Scripts\activate
# On macOS/Linux:
# source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Basic Commands
```bash
# Register a user
python run.py register --username customer1 --password CustomerPass123!

# Login (requires OTP verification)
python run.py login --username customer1 --password CustomerPass123!

# Browse products
python run.py list-products

# Add to cart
python run.py add-to-cart --product_id "03a3250b-3be7-45d8-b78c-b9cd25ee3f1d" --quantity 1

# View cart
python run.py view-cart

# Checkout
python run.py checkout

# Logout
python run.py logout
```

### Security Commands (Admin)
```bash
# List active sessions
python run.py list-sessions --username admin --password AdminPass123!

# Analyze threats
python run.py analyze-threats --username admin --password AdminPass123!

# Scan vulnerabilities
python run.py scan-vulnerabilities --username admin --password AdminPass123!
```

## Project Structure

```
ecommerce_cli_SSD_Project_updated/
├── run.py                           # Application entry point
├── requirements.txt                  # Python dependencies
├── app/                             # Main application code
│   ├── core/                        # Security and business logic
│   ├── models/                      # Data models
│   └── cli.py                       # Command-line interface
├── data/                            # Application data storage
├── config/                          # Configuration files
├── reports/                         # Project documentation
├── tests/                           # Test suite
├── demo_scripts/                    # Demonstration scripts
├── docs/                            # Documentation
├── logs/                            # Application logs
└── tools/                           # Security tools
```

## Testing

### Run Tests
```bash
# Run all tests
python -m pytest tests/ -v

# Run specific test categories
python -m pytest tests/test_auth.py -v
python -m pytest tests/test_product.py -v
python -m pytest tests/test_security_features.py -v

# Generate coverage report
python -m pytest tests/ --cov=app --cov-report=term
```

### Security Analysis
```bash
# Run security scans
bandit -r app/
flake8 app/
```

## Default Users

- **Admin**: admin / AdminPass123!
- **Demo User**: demo3 / DemoPass123!

## Documentation

- [`DEMONSTRATION_GUIDE.md`](./DEMONSTRATION_GUIDE.md) - Quick start guide
- [`PROJECT_STRUCTURE.md`](./PROJECT_STRUCTURE.md) - Detailed structure overview
- [`TESTING_EVIDENCE.md`](./TESTING_EVIDENCE.md) - Testing documentation
- [`DEMO_COMMANDS.md`](./DEMO_COMMANDS.md) - Demonstration commands

## Security Implementation

The application implements comprehensive security measures:

- **Authentication**: bcrypt password hashing with OTP verification
- **Session Management**: JWT tokens with automatic timeout
- **Data Protection**: Encrypted storage with key rotation
- **Rate Limiting**: Account lockout after failed attempts
- **Input Validation**: Comprehensive sanitization and validation
- **Audit Logging**: Detailed security event tracking

## Development

This project was developed as part of a secure software development course, demonstrating practical application of security best practices in a real-world scenario.

## License

This project is developed for educational purposes to demonstrate secure software development practices.
