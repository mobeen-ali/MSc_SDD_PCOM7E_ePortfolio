#!/usr/bin/env python3
"""
Demo script for OTP generation
"""

import sys
sys.path.append('..')

from app.models.user import User

def demo_otp():
    print("=== OTP Generation Demo ===")
    
    # Create a test user
    user = User("demo_user", "hashed_password", "user")
    
    # Generate OTP
    otp = user.get_otp_token()
    print(f"Generated OTP: {otp}")
    
    # Verify OTP
    is_valid = user.verify_otp(otp)
    print(f"OTP Verification: {'Valid' if is_valid else 'Invalid'}")
    
    # Test with wrong OTP
    wrong_otp = "123456"
    is_valid = user.verify_otp(wrong_otp)
    print(f"Wrong OTP Verification: {'Valid' if is_valid else 'Invalid'}")

if __name__ == "__main__":
    demo_otp() 