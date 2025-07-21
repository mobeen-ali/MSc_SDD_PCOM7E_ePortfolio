#!/usr/bin/env python3
"""
Video demonstration script for the Secure CLI E-Commerce Application
"""

import sys
sys.path.append('..')

def video_demo():
    print("=== Secure CLI E-Commerce Application - Video Demo Script ===")
    print()
    
    print("1. PROJECT OVERVIEW")
    print("   - Secure CLI E-Commerce Application with OWASP A01-A10 compliance")
    print("   - Python-based command-line interface using Click")
    print("   - Comprehensive security features and e-commerce functionality")
    print()
    
    print("2. SECURITY FEATURES (OWASP A01-A10)")
    print("   A01 - Session Management: JWT tokens, session timeout")
    print("   A02 - Cryptographic Failures: Key rotation, encryption")
    print("   A04 - Insecure Design: Threat modeling, risk assessment")
    print("   A06 - Vulnerable Components: Dependency scanning, advisories")
    print("   A07 - Authentication Failures: Rate limiting, account lockout")
    print("   A08 - Software Integrity: Data validation, checksums")
    print("   A09 - Security Logging: Advanced logging, SIEM integration")
    print("   A10 - SSRF: URL validation, network segmentation")
    print()
    
    print("3. E-COMMERCE FEATURES")
    print("   - User registration and authentication")
    print("   - Product catalog and inventory management")
    print("   - Shopping cart functionality")
    print("   - Order processing and payment simulation")
    print("   - Fraud detection and security validation")
    print()
    
    print("4. DEMONSTRATION STEPS")
    print("   Step 1: Show project structure and security features")
    print("   Step 2: Demonstrate user registration with password policy")
    print("   Step 3: Show login with OTP generation")
    print("   Step 4: Display product catalog")
    print("   Step 5: Demonstrate shopping cart operations")
    print("   Step 6: Show order processing and checkout")
    print("   Step 7: Demonstrate admin security features")
    print("   Step 8: Show comprehensive security testing")
    print()
    
    print("5. COMMAND EXAMPLES")
    print("   Registration: python run.py register --username demo --password DemoPass123!")
    print("   Login: python run.py login --username demo --password DemoPass123!")
    print("   List Products: python run.py list-products")
    print("   Add to Cart: python run.py add-to-cart --product_id <id> --quantity 1")
    print("   View Cart: python run.py view-cart")
    print("   Checkout: python run.py checkout")
    print("   Admin Commands: python run.py list-sessions --username admin --password AdminPass123!")
    print()
    
    print("6. SECURITY TESTING")
    print("   - Run comprehensive security tests")
    print("   - Show vulnerability scanning results")
    print("   - Demonstrate threat modeling analysis")
    print("   - Display security audit reports")
    print()
    
    print("7. TECHNICAL HIGHLIGHTS")
    print("   - Modular architecture with clear separation of concerns")
    print("   - Comprehensive error handling and logging")
    print("   - Secure session management with JWT tokens")
    print("   - Advanced cryptographic key management")
    print("   - Real-time security monitoring and alerting")
    print("   - Complete OWASP Top 10 compliance")
    print()
    
    print("8. CONCLUSION")
    print("   - Demonstrates secure software development practices")
    print("   - Shows comprehensive security implementation")
    print("   - Provides functional e-commerce capabilities")
    print("   - Ready for production deployment with additional hardening")
    print()

if __name__ == "__main__":
    video_demo() 