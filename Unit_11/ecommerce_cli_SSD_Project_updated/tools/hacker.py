"""
Filename: hacker.py
Author: Mobeen Ali
Date: July 2025

Purpose:
--------
Simulates a brute-force password attack on a hardcoded admin account
to demonstrate what happens when security mechanisms (e.g., weak passwords,
no lockout policy, invalid OTP) are in place or disabled.

This module is for **educational use only** as part of the MSc Secure Software Development course.
It is used to test resilience against password guessing and simulate attack logging.

Security Concepts Demonstrated:
-------------------------------
- Brute-force attack simulation using common weak passwords
- Importance of OTP validation in defense-in-depth
- Real-time logging of attacker behavior (OWASP A10: Logging & Monitoring)
- System response consistency (no leakage of failure details)

Note:
-----
- This module assumes the `admin` account exists
- The OTP is intentionally incorrect
"""


from app.core import auth
from app.core.logger import Logger

print("\nSimulated Brute-Force Attack on user 'admin'\n")
Logger.info("Hacker simulation started: Brute-force login attempt on 'admin'")

# Common weak password guesses
password_guesses = ['123', 'admin', 'test123', 'password']
otp_placeholder = '000000'  # Simulated incorrect OTP

for guess in password_guesses:
    # Attempt to authenticate using guessed password and invalid OTP
    result = auth.authenticate_user('admin', guess, otp_placeholder)
    if result:
        print(f"[SUCCESS] Access granted with password: '{guess}'")
        Logger.warning(f"[HACKER] Access granted with guess: {guess}")
    else:
        print(f"[FAILURE] Access denied with password: '{guess}'")
        Logger.info(f"[HACKER] Attempt failed with password: {guess}")

Logger.info("Hacker simulation completed.\n")
