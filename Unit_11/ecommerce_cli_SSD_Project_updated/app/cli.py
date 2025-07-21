"""
Filename: cli.py
Author: Mobeen Ali
Date: July 2025

Purpose:
---------
Defines the command-line interface (CLI) for the Secure E-Commerce Application.
Uses Click to route user commands securely to the appropriate logic for user management,
product operations, e-commerce features, and comprehensive security controls.

Key Features:
-------------
- User registration with advanced password policy (A07)
- Login with rate limiting and account lockout (A07)
- Session management with JWT tokens (A01)
- Product management with integrity validation (A08)
- Shopping cart and order management
- Comprehensive security features (A01-A10)
- Advanced logging and monitoring (A09)
- SSRF protection (A10)
- All operations are logged for auditing
"""

import click
from getpass import getpass
from app.core import auth
from app.models.product import Product
from app.models.cart import ShoppingCart
from app.models.order import order_manager, OrderStatus, PaymentStatus
from app.core.logger import Logger
from app.core.security import SecurityManager
from app.core.api_manager import APIManager
from app.core.session import session_manager
from app.core.crypto_manager import crypto_manager
from app.core.threat_model import threat_model
from app.core.vulnerability_scanner import vulnerability_scanner
from app.core.rate_limiter import rate_limiter
from app.core.integrity_manager import integrity_manager
from app.core.advanced_logger import advanced_logger, SecurityEventType
from app.core.ssrf_protection import ssrf_protection
from datetime import datetime
import os

# Global session token storage (in production, this would be more secure)
current_session_token = None

def _load_session_token():
    """Load session token from file."""
    try:
        if os.path.exists("data/current_session.txt"):
            with open("data/current_session.txt", "r") as f:
                return f.read().strip()
    except:
        pass
    return None

def _save_session_token(token):
    """Save session token to file."""
    try:
        with open("data/current_session.txt", "w") as f:
            f.write(token if token else "")
    except:
        pass

def _clear_session_token():
    """Clear session token from file."""
    _save_session_token(None)

# -------------------------------
# Root CLI Group
# -------------------------------
@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx):
    """Secure CLI E-commerce App with Complete OWASP A01-A10 Compliance"""
    # Check if user is logged in and get their role
    session_token = _load_session_token()
    user_role = None
    username = None
    
    if session_token:
        session_data = session_manager.validate_session(session_token)
        if session_data:
            user_role = session_data.get('role', 'user')
            username = session_data.get('username', 'Unknown')
    
    # If no command is provided, show context-aware help
    if ctx.invoked_subcommand is None:
        # Show context-aware help message
        if not user_role:
            click.echo("[SECURE] Secure CLI E-commerce App")
            click.echo("[COMMANDS] Available Commands (Not Logged In):")
            click.echo("   register    - Create a new account")
            click.echo("   login       - Sign in to your account")
            click.echo("   --help      - Show this help message")
            click.echo("")
            click.echo("[TIP] Use 'register' to create an account or 'login' to sign in")
        elif user_role == 'admin':
            click.echo("[SECURE] Secure CLI E-commerce App")
            click.echo(f"[USER] Logged in as: {username} (Admin)")
            click.echo("[COMMANDS] Available Commands:")
            click.echo("")
            click.echo("[SHOPPING] Shopping Commands:")
            click.echo("   list-products        - View all products")
            click.echo("   add-to-cart         - Add item to cart")
            click.echo("   view-cart           - View shopping cart")
            click.echo("   remove-from-cart    - Remove item from cart")
            click.echo("   set-shipping-address - Set delivery address")
            click.echo("   set-payment-method  - Choose payment method")
            click.echo("   checkout            - Complete purchase")
            click.echo("   my-orders           - View order history")
            click.echo("")
            click.echo("[ADMIN] Admin Commands:")
            click.echo("   add-product         - Add new product")
            click.echo("   update-product      - Modify existing product")
            click.echo("   delete-product      - Remove product")
            click.echo("")
            click.echo("[SECURITY] Security Commands:")
            click.echo("   list-sessions       - View active sessions")
            click.echo("   cleanup-sessions    - Remove expired sessions")
            click.echo("   unlock-account      - Unlock locked accounts")
            click.echo("   rate-limit-stats    - View rate limiting stats")
            click.echo("   rotate-keys         - Rotate cryptographic keys")
            click.echo("   validate-keys       - Validate key integrity")
            click.echo("   check-integrity     - Check data integrity")
            click.echo("   analyze-threats     - Analyze security threats")
            click.echo("   scan-vulnerabilities - Scan for vulnerabilities")
            click.echo("   check-advisories    - Check security advisories")
            click.echo("   security-report     - Generate security report")
            click.echo("   validate-logs       - Validate log integrity")
            click.echo("   test-url-validation - Test SSRF protection")
            click.echo("   toggle-security     - Toggle security features")
            click.echo("")
            click.echo("[ACCOUNT] Account Commands:")
            click.echo("   logout              - Sign out")
            click.echo("")
            click.echo("[TIP] Use '--help [command]' for detailed help")
        else:
            click.echo("[SECURE] Secure CLI E-commerce App")
            click.echo(f"[USER] Logged in as: {username} (Customer)")
            click.echo("[COMMANDS] Available Commands:")
            click.echo("")
            click.echo("[SHOPPING] Shopping Commands:")
            click.echo("   list-products        - View all products")
            click.echo("   add-to-cart         - Add item to cart")
            click.echo("   view-cart           - View shopping cart")
            click.echo("   remove-from-cart    - Remove item from cart")
            click.echo("   set-shipping-address - Set delivery address")
            click.echo("   set-payment-method  - Choose payment method")
            click.echo("   checkout            - Complete purchase")
            click.echo("   my-orders           - View order history")
            click.echo("")
            click.echo("[ACCOUNT] Account Commands:")
            click.echo("   logout              - Sign out")
            click.echo("")
            click.echo("[TIP] Use '--help [command]' for detailed help")

# -------------------------------
# Authentication Commands (A07)
# -------------------------------
@cli.command()
@click.option('--username', prompt='Username')
@click.option('--password', prompt='Password', hide_input=True)
def register(username, password):
    """Register a new user with advanced password policy (A07)."""
    try:
        # Check if username already exists FIRST
        users = auth._load_users()
        if username in users:
            click.echo("X Registration failed. Username already exists.")
            return
        
        # Validate password policy
        policy_result = rate_limiter.validate_password_policy(password, username)
        if not policy_result['valid']:
            click.echo("X Password does not meet security requirements:")
            for error in policy_result['errors']:
                click.echo(f"   - {error}")
            for warning in policy_result['warnings']:
                click.echo(f"   Warning: {warning}")
            return
        
        # Check rate limiting
        if not rate_limiter.check_rate_limit("127.0.0.1", "register"):
            click.echo("Rate limit exceeded. Please try again later.")
            return
        
        # Register user
        success = auth.register_user(username, password)
        if success:
            # Add password to history
            rate_limiter.add_password_to_history(username, password)
            
            # Log security event
            advanced_logger.log_security_event(
                SecurityEventType.LOGIN_SUCCESS,
                {
                    'username': username,
                    'action': 'registration',
                    'source_ip': '127.0.0.1'
                },
                'info'
            )
            
            click.echo("Registration successful!")
            click.echo("Password meets all security requirements.")
        else:
            click.echo("Registration failed due to system error.")
            
    except Exception as e:
        Logger.error(f"Registration error: {str(e)}")
        click.echo("Registration failed due to system error.")

@cli.command()
@click.option('--username', prompt='Username')
@click.option('--password', prompt='Password', hide_input=True)
def login(username, password):
    """Login with rate limiting and account lockout protection (A07)."""
    global current_session_token
    
    try:
        # Check account lockout
        if rate_limiter.is_account_locked(username):
            lockout_info = rate_limiter.get_lockout_info(username)
            click.echo(f"Account is locked until {lockout_info['locked_until']}")
            return
        
        # Check rate limiting
        if not rate_limiter.check_rate_limit("127.0.0.1", "login"):
            click.echo("Rate limit exceeded. Please try again later.")
            return
        
        # Attempt login
        success, otp = auth.login_user(username, password)
        
        if success:
            # Display OTP and prompt user to enter it
            click.echo(f"Your OTP: {otp}")
            user_otp = click.prompt("Enter the OTP to complete login", type=str)
            
            # Verify OTP
            if auth.verify_otp(username, user_otp):
                # Reset failed attempts on successful login
                rate_limiter.failed_attempts[username] = []
                
                # Get user role from database
                users = auth._load_users()
                user_role = users.get(username, {}).get('role', 'user')
                
                # Create session with actual user role
                user_data = {'username': username, 'role': user_role}
                session_token = session_manager.create_session(user_data)
                _save_session_token(session_token)
                
                # Log security event
                advanced_logger.log_security_event(
                    SecurityEventType.LOGIN_SUCCESS,
                    {
                        'username': username,
                        'source_ip': '127.0.0.1',
                        'session_id': session_manager.sessions[list(session_manager.sessions.keys())[0]]['session_id']
                    },
                    'info'
                )
                
                click.echo("Login successful!")
                if user_role == 'admin':
                    click.echo("Session created. You can now use admin commands.")
                else:
                    click.echo("Session created. You can now use shopping commands.")
            else:
                # Record failed OTP attempt
                should_lock = rate_limiter.record_failed_attempt(username, "127.0.0.1")
                
                # Log security event
                advanced_logger.log_security_event(
                    SecurityEventType.LOGIN_FAILURE,
                    {
                        'username': username,
                        'source_ip': '127.0.0.1',
                        'reason': 'invalid_otp'
                    },
                    'warning'
                )
                
                if should_lock:
                    click.echo("Account locked due to too many failed attempts.")
                else:
                    remaining_attempts = 5 - len(rate_limiter.failed_attempts.get(username, []))
                    click.echo(f"Invalid OTP. {remaining_attempts} attempts remaining.")
        else:
            # Record failed attempt
            should_lock = rate_limiter.record_failed_attempt(username, "127.0.0.1")
            
            # Log security event
            advanced_logger.log_security_event(
                SecurityEventType.LOGIN_FAILURE,
                {
                    'username': username,
                    'source_ip': '127.0.0.1',
                    'reason': 'invalid_credentials'
                },
                'warning'
            )
            
            if should_lock:
                click.echo("Account locked due to too many failed attempts.")
            else:
                remaining_attempts = 5 - len(rate_limiter.failed_attempts.get(username, []))
                click.echo(f"Login failed. {remaining_attempts} attempts remaining.")
                
    except Exception as e:
        Logger.error(f"Login error: {str(e)}")
        click.echo("Login failed due to system error.")

@cli.command()
def logout():
    """Logout and invalidate session."""
    try:
        session_token = _load_session_token()
        if session_token:
            session_manager.invalidate_session(session_token)
            _clear_session_token()
            
            # Log security event
            advanced_logger.log_security_event(
                SecurityEventType.LOGOUT,
                {
                    'source_ip': '127.0.0.1'
                },
                'info'
            )
            
            click.echo("Logout successful. Session invalidated.")
        else:
            click.echo("No active session to logout.")
            
    except Exception as e:
        Logger.error(f"Logout error: {str(e)}")
        click.echo("Logout failed due to system error.")

# -------------------------------
# Session Management Commands (A01)
# -------------------------------
@cli.command()
@click.option('--username', prompt='Admin Username')
@click.option('--password', prompt='Admin Password', hide_input=True)
def list_sessions(username, password):
    """List active sessions (Admin only)."""
    try:
        # Verify admin credentials
        success, _ = auth.login_user(username, password)
        if not success or username != 'admin':
            click.echo("X Admin access required.")
            return
        
        sessions = session_manager.get_active_sessions()
        if sessions:
            click.echo("  Active Sessions:")
            for session in sessions:
                created_at = session['created_at']
                expires_at = session['expires_at']
                username = session['username']
                role = session['role']
                
                # Calculate time remaining
                from datetime import datetime
                current_time = datetime.utcnow()
                expires_datetime = datetime.fromisoformat(expires_at)
                time_remaining = expires_datetime - current_time
                
                # Format time remaining
                if time_remaining.total_seconds() > 0:
                    minutes_remaining = int(time_remaining.total_seconds() / 60)
                    time_status = f"Expires in {minutes_remaining} minutes"
                else:
                    time_status = "EXPIRED"
                
                click.echo(f"   - User: {username} ({role})")
                click.echo(f"     Created: {created_at}")
                click.echo(f"     Expires: {expires_at}")
                click.echo(f"     Status: {time_status}")
                click.echo("")
        else:
            click.echo("   No active sessions.")
            
    except Exception as e:
        Logger.error(f"List sessions error: {str(e)}")
        click.echo("X Failed to list sessions.")

@cli.command()
@click.option('--username', prompt='Admin Username')
@click.option('--password', prompt='Admin Password', hide_input=True)
def cleanup_sessions(username, password):
    """Clean up expired sessions (Admin only)."""
    try:
        # Verify admin credentials
        success, _ = auth.login_user(username, password)
        if not success or username != 'admin':
            click.echo("X Admin access required.")
            return
        
        session_manager.cleanup_expired_sessions()
        click.echo("  Expired sessions cleaned up.")
        
    except Exception as e:
        Logger.error(f"Cleanup sessions error: {str(e)}")
        click.echo("X Failed to cleanup sessions.")

# -------------------------------
# Rate Limiting Commands (A07)
# -------------------------------
@cli.command()
@click.option('--username', prompt='Admin Username')
@click.option('--password', prompt='Admin Password', hide_input=True)
def unlock_account(username, password):
    """Unlock a rate-limited account (Admin only)."""
    try:
        # Verify admin credentials
        success, _ = auth.login_user(username, password)
        if not success or username != 'admin':
            click.echo("X Admin access required.")
            return

        target_username = click.prompt("Enter username to unlock")
        success = rate_limiter.unlock_account(target_username)

        if success:
            click.echo(f"  Account {target_username} unlocked successfully.")
        else:
            click.echo(f"   Account {target_username} was not locked.")
            
    except Exception as e:
        Logger.error(f"Unlock account error: {str(e)}")
        click.echo("X Failed to unlock account.")

@cli.command()
@click.option('--username', prompt='Admin Username')
@click.option('--password', prompt='Admin Password', hide_input=True)
def rate_limit_stats(username, password):
    """Get rate limiting statistics (Admin only)."""
    try:
        # Verify admin credentials
        success, _ = auth.login_user(username, password)
        if not success or username != 'admin':
            click.echo("X Admin access required.")
            return
        
        stats = rate_limiter.get_rate_limit_stats()
        click.echo("  Rate Limiting Statistics:")
        click.echo(f"   - Active Lockouts: {stats['active_lockouts']}")
        click.echo(f"   - Rate Limited IPs: {stats['total_rate_limited_ips']}")
        click.echo(f"   - Failed Attempts by User: {stats['failed_attempts_by_user']}")
        
    except Exception as e:
        Logger.error(f"Rate limit stats error: {str(e)}")
        click.echo("X Failed to get rate limit statistics.")

# -------------------------------
# Cryptographic Commands (A02)
# -------------------------------
@cli.command()
@click.option('--username', prompt='Admin Username')
@click.option('--password', prompt='Admin Password', hide_input=True)
def rotate_keys(username, password):
    """Rotate cryptographic keys (Admin only)."""
    try:
        # Verify admin credentials
        success, _ = auth.login_user(username, password)
        if not success or username != 'admin':
            click.echo("X Admin access required.")
            return
        
        # Get statistics before rotation
        stats_before = crypto_manager.get_key_statistics()
        
        # Perform key rotation
        success = crypto_manager.rotate_keys()
        
        if success:
            # Get statistics after rotation
            stats_after = crypto_manager.get_key_statistics()
            
            # Validate keys after rotation
            validation_success = crypto_manager.validate_key_integrity()
            
            click.echo("  [ROTATION] Cryptographic Key Rotation Results:")
            click.echo("")
            click.echo("  [BEFORE] Key Statistics (Before Rotation):")
            click.echo(f"   - Total Keys: {stats_before['total_keys']}")
            click.echo(f"   - Active Keys: {stats_before['active_keys']}")
            click.echo(f"   - Expired Keys: {stats_before['expired_keys']}")
            click.echo("")
            click.echo("  [AFTER] Key Statistics (After Rotation):")
            click.echo(f"   - Total Keys: {stats_after['total_keys']}")
            click.echo(f"   - Active Keys: {stats_after['active_keys']}")
            click.echo(f"   - Expired Keys: {stats_after['expired_keys']}")
            click.echo("")
            click.echo("  [CONFIG] Rotation Configuration:")
            click.echo(f"   - Rotation Interval: {stats_after['rotation_interval_days']} days")
            click.echo(f"   - Max Key Age: {stats_after['max_key_age_days']} days")
            click.echo("")
            click.echo("  [VALIDATION] Key Integrity Check:")
            if validation_success:
                click.echo("   - All keys validated successfully")
            else:
                click.echo("   - Key validation issues detected")
            click.echo("")
            click.echo("  [STATUS] Rotation completed successfully!")
        else:
            click.echo("X [ERROR] Key rotation failed.")
            
    except Exception as e:
        Logger.error(f"Rotate keys error: {str(e)}")
        click.echo("X [ERROR] Failed to rotate keys.")

@cli.command()
@click.option('--username', prompt='Admin Username')
@click.option('--password', prompt='Admin Password', hide_input=True)
def validate_keys(username, password):
    """Validate cryptographic key integrity (Admin only)."""
    try:
        # Verify admin credentials
        success, _ = auth.login_user(username, password)
        if not success or username != 'admin':
            click.echo("X Admin access required.")
            return

        success = crypto_manager.validate_key_integrity()
        if success:
            click.echo("  Cryptographic keys validated successfully.")
        else:
            click.echo("X Key validation failed.")
            
    except Exception as e:
        Logger.error(f"Validate keys error: {str(e)}")
        click.echo("X Failed to validate keys.")

# -------------------------------
# Integrity Commands (A08)
# -------------------------------
@cli.command()
@click.option('--username', prompt='Admin Username')
@click.option('--password', prompt='Admin Password', hide_input=True)
def check_integrity(username, password):
    """Check data and software integrity (Admin only)."""
    try:
        # Verify admin credentials
        success, _ = auth.login_user(username, password)
        if not success or username != 'admin':
            click.echo("X Admin access required.")
            return

        # Monitor all critical files
        results = integrity_manager.monitor_all_critical_files()
        
        click.echo("  Integrity Check Results:")
        for file_path, result in results.items():
            status = "  " if result['integrity_valid'] else "X"
            click.echo(f"   {status} {file_path}")
            if result.get('changes_detected'):
                click.echo(f"       [WARN]  Changes detected!")
        
        # Validate supply chain
        supply_chain = integrity_manager.validate_supply_chain_integrity()
        if supply_chain['valid']:
            click.echo("   Supply chain integrity validated.")
        else:
            click.echo("X Supply chain integrity issues detected.")
            for warning in supply_chain['warnings']:
                click.echo(f"    [WARN]  {warning}")

    except Exception as e:
        Logger.error(f"Check integrity error: {str(e)}")
        click.echo("X Failed to check integrity.")

# -------------------------------
# Threat Modeling Commands (A04)
# -------------------------------
@cli.command()
@click.option('--username', prompt='Admin Username')
@click.option('--password', prompt='Admin Password', hide_input=True)
def analyze_threats(username, password):
    """Analyze threats using comprehensive threat modeling (Admin only)."""
    try:
        # Verify admin credentials
        success, _ = auth.login_user(username, password)
        if not success or username != 'admin':
            click.echo("X Admin access required.")
            return
        
        analysis = threat_model.analyze_threats()
        
        click.echo("   Threat Analysis Results:")
        click.echo(f"   - Total Threats: {analysis['summary']['total_threats']}")
        click.echo(f"   - Critical Threats: {analysis['summary']['critical_threats']}")
        click.echo(f"   - High Threats: {analysis['summary']['high_threats']}")
        click.echo(f"   - Medium Threats: {analysis['summary']['medium_threats']}")
        click.echo(f"   - Low Threats: {analysis['summary']['low_threats']}")
        click.echo(f"   - Mitigated Threats: {analysis['summary']['mitigated_threats']}")
        click.echo(f"   - Open Threats: {analysis['summary']['open_threats']}")
        
        # Show individual threats
        click.echo("\n  Threat Details:")
        for threat_id, threat_data in threat_model.threats.items():
            status_label = "[PROTECTED]" if threat_data['status'] == 'Mitigated' else "[NEEDS ATTENTION]"
            click.echo(f"   {status_label} {threat_data['title']} ({threat_data['risk_level']})")

    except Exception as e:
        Logger.error(f"Analyze threats error: {str(e)}")
        click.echo("X Failed to analyze threats.")

# -------------------------------
# Vulnerability Scanning Commands (A06)
# -------------------------------
@cli.command()
@click.option('--username', prompt='Admin Username')
@click.option('--password', prompt='Admin Password', hide_input=True)
def scan_vulnerabilities(username, password):
    """Scan dependencies for vulnerabilities (Admin only)."""
    try:
        # Verify admin credentials
        success, _ = auth.login_user(username, password)
        if not success or username != 'admin':
            click.echo("X Admin access required.")
            return
        
        results = vulnerability_scanner.scan_dependencies()
        
        click.echo("  Vulnerability Scan Results:")
        click.echo(f"   - Components Scanned: {results['total_components']}")
        click.echo(f"   - Vulnerable Components: {results['vulnerable_components']}")
        click.echo(f"   - Outdated Components: {results['outdated_components']}")
        click.echo(f"   - Secure Components: {results['secure_components']}")
        
        # Show component details
        if results['components']:
            click.echo("\n  Component Status:")
            for component_name, component_data in results['components'].items():
                status_icon = "  " if component_data['status'] == 'Secure' else "X"
                click.echo(f"   {status_icon} {component_name} ({component_data['current_version']}) - {component_data['status']}")
        
        # Show recommendations
        if results['recommendations']:
            click.echo("\n  Recommendations:")
            for rec in results['recommendations'][:3]:  # Show first 3
                click.echo(f"   - {rec}")
            
    except Exception as e:
        Logger.error(f"Scan vulnerabilities error: {str(e)}")
        click.echo("X Failed to scan vulnerabilities.")

@cli.command()
@click.option('--username', prompt='Admin Username')
@click.option('--password', prompt='Admin Password', hide_input=True)
def check_advisories(username, password):
    """Check security advisories (Admin only)."""
    try:
        # Verify admin credentials
        success, _ = auth.login_user(username, password)
        if not success or username != 'admin':
            click.echo("X Admin access required.")
            return

        advisories = vulnerability_scanner.check_security_advisories()
        
        click.echo("  Security Advisories:")
        click.echo(f"   - Total Advisories: {len(advisories)}")
        
        if advisories:
            click.echo("\n  Advisory Details:")
            for advisory in advisories[:5]:  # Show first 5
                click.echo(f"   - {advisory.get('affected_components', ['Unknown'])[0]}: {advisory.get('title', 'No title')}")
                click.echo(f"     Severity: {advisory.get('severity', 'Unknown')}")
                click.echo(f"     Source: {advisory.get('source', 'Unknown')}")
                click.echo(f"     Published: {advisory.get('published_date', 'Unknown')}")
                click.echo("")
        else:
            click.echo("   No security advisories found.")
            
    except Exception as e:
        Logger.error(f"Check advisories error: {str(e)}")
        click.echo("X Failed to check advisories.")

# -------------------------------
# Advanced Logging Commands (A09)
# -------------------------------
@cli.command()
@click.option('--username', prompt='Admin Username')
@click.option('--password', prompt='Admin Password', hide_input=True)
def security_report(username, password):
    """Generate comprehensive security report (Admin only)."""
    try:
        # Verify admin credentials
        success, _ = auth.login_user(username, password)
        if not success or username != 'admin':
            click.echo("X Admin access required.")
            return
        
        report = advanced_logger.get_security_report()
        
        click.echo("  Security Report:")
        click.echo(f"   - Total Events: {report['metrics']['total_events']}")
        click.echo(f"   - Security Incidents: {report['metrics']['security_incidents']}")
        click.echo(f"   - Anomalies Detected: {report['metrics']['anomalies_detected']}")
        click.echo(f"   - Active Incidents: {report['recent_activity']['active_incidents']}")
        
        if report['recommendations']:
            click.echo("\n  Recommendations:")
            for rec in report['recommendations']:
                click.echo(f"   - {rec}")
                
    except Exception as e:
        Logger.error(f"Security report error: {str(e)}")
        click.echo("X Failed to generate security report.")

@cli.command()
@click.option('--username', prompt='Admin Username')
@click.option('--password', prompt='Admin Password', hide_input=True)
def validate_logs(username, password):
    """Validate log integrity (Admin only)."""
    try:
        # Verify admin credentials
        success, _ = auth.login_user(username, password)
        if not success or username != 'admin':
            click.echo("X Admin access required.")
            return
        
        result = advanced_logger.validate_log_integrity()
        
        click.echo("  Log Integrity Validation:")
        click.echo(f"   - Valid Entries: {result['valid_entries']}")
        click.echo(f"   - Invalid Entries: {result['invalid_entries']}")
        
        if result['integrity_valid']:
            click.echo("   Log integrity validated successfully.")
        else:
            click.echo("X Log integrity issues detected.")

    except Exception as e:
        Logger.error(f"Validate logs error: {str(e)}")
        click.echo("X Failed to validate logs.")

# -------------------------------
# SSRF Protection Commands (A10)
# -------------------------------
@cli.command()
@click.option('--username', prompt='Admin Username')
@click.option('--password', prompt='Admin Password', hide_input=True)
def test_url_validation(username, password):
    """Test URL validation for SSRF protection (Admin only)."""
    try:
        # Verify admin credentials
        success, _ = auth.login_user(username, password)
        if not success or username != 'admin':
            click.echo("X Admin access required.")
            return
        
        test_urls = [
            "https://api.example.com/data",
            "http://localhost:8080/admin",
            "file:///etc/passwd",
            "http://127.0.0.1:3306",
            "https://external-service.com/api"
        ]
        
        results = ssrf_protection.test_url_validation(test_urls)
        
        click.echo("  SSRF URL Validation Test:")
        click.echo(f"   - Total Tested: {results['total_tested']}")
        click.echo(f"   - Valid URLs: {results['valid_urls']}")
        click.echo(f"   - Invalid URLs: {results['invalid_urls']}")
        click.echo(f"   - SSRF Attempts Detected: {results['ssrf_attempts_detected']}")
        
        for result in results['results']:
            status = "  " if result['valid'] else "X"
            ssrf_status = " [ALERT]" if result['ssrf_detected'] else ""
            click.echo(f"   {status} {result['url']} {ssrf_status}")
            
    except Exception as e:
        Logger.error(f"Test URL validation error: {str(e)}")
        click.echo("X Failed to test URL validation.")

# -------------------------------
# Product Management Commands (with Session Validation)
# -------------------------------
@cli.command()
@click.option('--name', prompt='Product Name')
@click.option('--price', prompt='Price', type=float)
@click.option('--stock', prompt='Stock Quantity', type=int)
@click.option('--description', prompt='Description')
def add_product(name, price, stock, description):
    """Add a new product (Admin only)."""
    global current_session_token
    
    try:
        # Load session token from file
        current_session_token = _load_session_token()
        
        # Validate session
        if not current_session_token:
            click.echo("X Please login first.")
            return
        
        session_data = session_manager.validate_session(current_session_token)
        if not session_data:
            click.echo("X Invalid or expired session. Please login again.")
            return
        
        # Check admin role
        if session_data.get('role') != 'admin':
            click.echo("X Admin access required for product management.")
            return
        
        # Create product with integrity protection
        product = Product(name, price, stock, description)
        
        # Store with integrity checks
        product_data = product.to_dict()
        success = integrity_manager.store_data_with_integrity(
            f"product_{product.product_id}",
            str(product_data)
        )
        
        if success:
            # Save to storage
            from app.core.auth import load_products, save_products
            products = load_products()
            products[product.product_id] = product.to_dict()
            save_products(products)
            
            # Log security event
            advanced_logger.log_security_event(
                SecurityEventType.DATA_MODIFIED,
                {
                    'user_id': session_data['username'],
                    'action': 'add_product',
                    'product_id': product.product_id,
                    'source_ip': '127.0.0.1'
                },
                'info'
            )
            
            click.echo(f"   Product '{name}' added successfully!")
            click.echo(f"  Product ID: {product.product_id}")
        else:
            click.echo("X Failed to add product due to integrity check failure.")
            
    except Exception as e:
        Logger.error(f"Add product error: {str(e)}")
        click.echo("X Failed to add product.")

@cli.command()
@click.option('--product_id', prompt='Product ID')
@click.option('--name', prompt='New Name')
@click.option('--price', prompt='New Price', type=float)
@click.option('--stock', prompt='New Stock', type=int)
@click.option('--description', prompt='New Description')
def update_product(product_id, name, price, stock, description):
    """Update an existing product (Admin only)."""
    global current_session_token
    
    try:
        # Load session token from file
        current_session_token = _load_session_token()
        
        # Validate session
        if not current_session_token:
            click.echo("X Please login first.")
            return
        
        session_data = session_manager.validate_session(current_session_token)
        if not session_data:
            click.echo("X Invalid or expired session. Please login again.")
            return
        
        # Check admin role
        if session_data.get('role') != 'admin':
            click.echo("X Admin access required for product management.")
            return
        
        # Load and update product
        from app.core.auth import load_products, save_products
        products = load_products()
        
        if product_id not in products:
            click.echo("X Product not found.")
            return
        
        # Update product data
        product_data = products[product_id]
        product_data['name'] = name
        product_data['price'] = price
        product_data['stock'] = stock
        product_data['description'] = description
        product_data['updated_at'] = datetime.utcnow().isoformat()
        
        # Validate integrity
        success = integrity_manager.store_data_with_integrity(
            f"product_{product_id}",
            str(product_data)
        )
        
        if success:
            # Save updated product
            products[product_id] = product_data
            save_products(products)
            
            # Log security event
            advanced_logger.log_security_event(
                SecurityEventType.DATA_MODIFIED,
                {
                    'user_id': session_data['username'],
                    'action': 'update_product',
                    'product_id': product_id,
                    'source_ip': '127.0.0.1'
                },
                'info'
            )
            
            click.echo(f"   Product '{name}' updated successfully!")
            click.echo(f"  Product ID: {product_id}")
        else:
            click.echo("X Failed to update product due to integrity check failure.")
            
    except Exception as e:
        Logger.error(f"Update product error: {str(e)}")
        click.echo("X Failed to update product.")

@cli.command()
@click.option('--product_id', prompt='Product ID')
def delete_product(product_id):
    """Delete a product (Admin only)."""
    global current_session_token
    
    try:
        # Load session token from file
        current_session_token = _load_session_token()
        
        # Validate session
        if not current_session_token:
            click.echo("X Please login first.")
            return
        
        session_data = session_manager.validate_session(current_session_token)
        if not session_data:
            click.echo("X Invalid or expired session. Please login again.")
            return
        
        # Check admin role
        if session_data.get('role') != 'admin':
            click.echo("X Admin access required for product management.")
            return
        
        # Load and delete product
        from app.core.auth import load_products, save_products
        products = load_products()
        
        if product_id not in products:
            click.echo("X Product not found.")
            return
        
        # Get product name before deletion
        product_name = products[product_id]['name']
        
        # Validate integrity before deletion
        success = integrity_manager.store_data_with_integrity(
            f"product_deletion_{product_id}",
            f"deleted_product_{product_id}_{datetime.utcnow().isoformat()}"
        )
        
        if success:
            # Delete the product
            del products[product_id]
            save_products(products)
            
            # Log security event
            advanced_logger.log_security_event(
                SecurityEventType.DATA_MODIFIED,
                {
                    'user_id': session_data['username'],
                    'action': 'delete_product',
                    'product_id': product_id,
                    'source_ip': '127.0.0.1'
                },
                'info'
            )
            
            click.echo(f"   Product '{product_name}' deleted successfully!")
            click.echo(f"  Product ID: {product_id}")
        else:
            click.echo("X Failed to delete product due to integrity check failure.")
        
    except Exception as e:
        Logger.error(f"Delete product error: {str(e)}")
        click.echo("X Failed to delete product.")

@cli.command()
def list_products():
    """List all products."""
    try:
        from app.core.auth import load_products
        products = load_products()
        
        if products:
            click.echo("  Available Products:")
            for product_id, product in products.items():
                click.echo(f"     {product_id}")
                click.echo(f"     {product['name']}")
                click.echo(f"    ${product['price']}")
                click.echo(f"     Stock: {product['quantity']}")
                click.echo(f"     {product['description']}")
                click.echo("   " + "-" * 40)
        else:
            click.echo(" No products available.")
            
    except Exception as e:
        Logger.error(f"List products error: {str(e)}")
        click.echo("X Failed to list products.")

# -------------------------------
# E-commerce Commands
# -------------------------------
@cli.command()
@click.option('--product_id', prompt='Product ID')
@click.option('--quantity', prompt='Quantity', type=int, default=1)
def add_to_cart(product_id, quantity):
    """Add product to shopping cart (requires valid session)."""
    global current_session_token
    
    try:
        # Load session token from file
        current_session_token = _load_session_token()
        
        # Validate session
        if not current_session_token:
            click.echo("X Please login first.")
            return
        
        session_data = session_manager.validate_session(current_session_token)
        if not session_data:
            click.echo("X Invalid or expired session. Please login again.")
            return
        
        # Create cart and add item
        cart = ShoppingCart(session_data['username'])
        success = cart.add_item(product_id, quantity)
        
        if success:
            click.echo(f"   Added {quantity} of product {product_id} to cart!")
        else:
            click.echo("X Failed to add item to cart.")
            
    except Exception as e:
        Logger.error(f"Add to cart error: {str(e)}")
        click.echo("X Failed to add item to cart.")

@cli.command()
def view_cart():
    """View shopping cart contents (requires valid session)."""
    global current_session_token
    
    try:
        # Load session token from file
        current_session_token = _load_session_token()
        
        # Validate session
        if not current_session_token:
            click.echo("X Please login first.")
            return
        
        session_data = session_manager.validate_session(current_session_token)
        if not session_data:
            click.echo("X Invalid or expired session. Please login again.")
            return
        
        # Get cart summary
        cart = ShoppingCart(session_data['username'])
        summary = cart.get_cart_summary()
        
        if summary['items']:
            click.echo("🛒 Shopping Cart:")
            for item in summary['items']:
                status = "  " if item['available'] else "X"
                click.echo(f"   {status} {item['name']} x{item['quantity']} = ${item['item_total']:.2f}")
            
            click.echo(f"\n Subtotal: ${summary['subtotal']:.2f}")
            click.echo(f" Shipping: ${summary['shipping_cost']:.2f}")
            click.echo(f"  Tax: ${summary['tax_amount']:.2f}")
            click.echo(f" Total: ${summary['total']:.2f}")
        else:
            click.echo(" Your cart is empty.")
            
    except Exception as e:
        Logger.error(f"View cart error: {str(e)}")
        click.echo("X Failed to view cart.")

@cli.command()
@click.option('--product_id', prompt='Product ID')
def remove_from_cart(product_id):
    """Remove item from shopping cart (requires valid session)."""
    global current_session_token
    
    try:
        # Load session token from file
        current_session_token = _load_session_token()
        
        # Validate session
        if not current_session_token:
            click.echo("X Please login first.")
            return
        
        session_data = session_manager.validate_session(current_session_token)
        if not session_data:
            click.echo("X Invalid or expired session. Please login again.")
            return
        
        # Remove item from cart
        cart = ShoppingCart(session_data['username'])
        success = cart.remove_item(product_id)
        
        if success:
            click.echo(f"   Removed product {product_id} from cart!")
        else:
            click.echo("X Failed to remove item from cart.")
            
    except Exception as e:
        Logger.error(f"Remove from cart error: {str(e)}")
        click.echo("X Failed to remove item from cart.")

@cli.command()
@click.option('--street', prompt='Street Address')
@click.option('--city', prompt='City')
@click.option('--state', prompt='State/Province')
@click.option('--zip_code', prompt='ZIP/Postal Code')
@click.option('--country', prompt='Country', default='USA')
def set_shipping_address(street, city, state, zip_code, country):
    """Set shipping address for checkout (requires valid session)."""
    global current_session_token
    
    try:
        # Load session token from file
        current_session_token = _load_session_token()
        
        # Validate session
        if not current_session_token:
            click.echo("X Please login first.")
            return
        
        session_data = session_manager.validate_session(current_session_token)
        if not session_data:
            click.echo("X Invalid or expired session. Please login again.")
            return
        
        # Create shipping address
        address = {
            'street': street,
            'city': city,
            'state': state,
            'zip_code': zip_code,
            'country': country
        }
        
        # Set shipping address in cart
        cart = ShoppingCart(session_data['username'])
        success = cart.set_shipping_address(address)
        
        if success:
            click.echo("   Shipping address set successfully!")
            click.echo(f"   Address: {street}, {city}, {state} {zip_code}, {country}")
        else:
            click.echo("X Failed to set shipping address.")
            
    except Exception as e:
        Logger.error(f"Set shipping address error: {str(e)}")
        click.echo("X Failed to set shipping address.")

@cli.command()
@click.option('--payment_method', prompt='Payment Method', type=click.Choice(['credit_card', 'paypal', 'bank_transfer']))
def set_payment_method(payment_method):
    """Set payment method for checkout (requires valid session)."""
    global current_session_token
    
    try:
        # Load session token from file
        current_session_token = _load_session_token()
        
        # Validate session
        if not current_session_token:
            click.echo("X Please login first.")
            return
        
        session_data = session_manager.validate_session(current_session_token)
        if not session_data:
            click.echo("X Invalid or expired session. Please login again.")
            return
        
        # Set payment method in cart
        cart = ShoppingCart(session_data['username'])
        success = cart.set_payment_method(payment_method)
        
        if success:
            click.echo(f"   Payment method set successfully!")
            click.echo(f"   Method: {payment_method}")
        else:
            click.echo("X Failed to set payment method.")
            
    except Exception as e:
        Logger.error(f"Set payment method error: {str(e)}")
        click.echo("X Failed to set payment method.")

@cli.command()
def checkout():
    """Checkout and create order (requires valid session)."""
    global current_session_token
    
    try:
        # Load session token from file
        current_session_token = _load_session_token()
        
        # Validate session
        if not current_session_token:
            click.echo("X Please login first.")
            return
        
        session_data = session_manager.validate_session(current_session_token)
        if not session_data:
            click.echo("X Invalid or expired session. Please login again.")
            return
        
        # Get cart and create order
        cart = ShoppingCart(session_data['username'])
        summary = cart.get_cart_summary()
        
        if not summary['items']:
            click.echo("X Cart is empty. Cannot checkout.")
            return
        
        # Validate shipping address
        if not summary['shipping_address']:
            click.echo("X Please set shipping address first.")
            return

        # Validate payment method
        if not summary['payment_method']:
            click.echo("X Please set payment method first.")
            return

        # Create order
        order = order_manager.create_order(session_data['username'], cart)
        
        if order:
            click.echo(f"   Order created successfully!")
            click.echo(f"  Order ID: {order.order_id}")
            click.echo(f" Total: ${order.total:.2f}")
            click.echo(f" Status: {order.status.value}")
        else:
            click.echo("X Failed to create order.")
            
    except Exception as e:
        Logger.error(f"Checkout error: {str(e)}")
        click.echo("X Failed to checkout.")

@cli.command()
def my_orders():
    """View user's order history (requires valid session)."""
    global current_session_token
    
    try:
        # Load session token from file
        current_session_token = _load_session_token()
        
        # Validate session
        if not current_session_token:
            click.echo("X Please login first.")
            return
        
        session_data = session_manager.validate_session(current_session_token)
        if not session_data:
            click.echo("X Invalid or expired session. Please login again.")
            return
        
        # Get user orders
        orders = order_manager.get_user_orders(session_data['username'])
        
        if orders:
            click.echo("  Your Orders:")
            for order in orders:
                click.echo(f"     {order.order_id}")
                click.echo(f"    Status: {order.status.value}")
                click.echo(f"    Payment: {order.payment_status.value}")
                click.echo(f"    Total: ${order.total:.2f}")
                click.echo(f"    Created: {order.created_at.strftime('%Y-%m-%d %H:%M')}")
                if order.tracking_number:
                    click.echo(f"    Tracking: {order.tracking_number}")
                click.echo("   " + "-" * 40)
        else:
            click.echo("  No orders found.")
            
    except Exception as e:
        Logger.error(f"My orders error: {str(e)}")
        click.echo("X Failed to get orders.")

# -------------------------------
# Security Toggle Command
# -------------------------------
@cli.command()
@click.option('--username', prompt='Admin Username')
@click.option('--password', prompt='Admin Password', hide_input=True)
def toggle_security(username, password):
    """Toggle security features (Admin only)."""
    try:
        # Verify admin credentials
        success, _ = auth.login_user(username, password)
        if not success or username != 'admin':
            click.echo("X Admin access required.")
            return
        
        security_manager = SecurityManager()
        current_status = security_manager.get_security_status()
        
        # Toggle security
        new_status = not current_status['enabled']
        security_manager.toggle_security(new_status)
        
        status_text = "enabled" if new_status else "disabled"
        click.echo(f"   Security features {status_text}.")
        
    except Exception as e:
        Logger.error(f"Toggle security error: {str(e)}")
        click.echo("X Failed to toggle security.")

# -------------------------------
# Main Entry Point
# -------------------------------
if __name__ == '__main__':
    cli()
