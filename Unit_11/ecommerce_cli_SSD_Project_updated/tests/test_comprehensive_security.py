"""
Filename: test_comprehensive_security.py
Author: Mobeen Ali
Date: July 2025

Purpose:
--------
Comprehensive tests for all OWASP A01-A10 security features and enhanced e-commerce functionality.
Tests rate limiting, integrity management, advanced logging, SSRF protection, and e-commerce features.

Security Features Tested:
-------------------------
- OWASP A07: Rate Limiting and Advanced Authentication
- OWASP A08: Data and Software Integrity
- OWASP A09: Advanced Logging and Monitoring
- OWASP A10: SSRF Protection
- Enhanced E-commerce: Shopping Cart and Order Management
"""

import os
import pytest
import tempfile
import shutil
from datetime import datetime, timedelta
from decimal import Decimal

from app.core.rate_limiter import rate_limiter
from app.core.integrity_manager import integrity_manager
from app.core.advanced_logger import advanced_logger, SecurityEventType
from app.core.ssrf_protection import ssrf_protection
from app.models.cart import ShoppingCart, CartItem
from app.models.order import order_manager, Order, OrderStatus, PaymentStatus


class TestRateLimiting:
    """Test OWASP A07: Rate Limiting and Advanced Authentication."""
    
    def test_rate_limit_check(self):
        """Test rate limiting functionality."""
        # Test normal rate limit check
        result = rate_limiter.check_rate_limit("192.168.1.1", "login")
        assert result is True
        
        # Test multiple rapid requests
        for _ in range(15):  # Exceed limit
            rate_limiter.check_rate_limit("192.168.1.2", "login")
        
        # Should be rate limited
        result = rate_limiter.check_rate_limit("192.168.1.2", "login")
        assert result is False
    
    def test_account_lockout(self):
        """Test account lockout mechanism."""
        username = "testuser_lockout"
        
        # Record failed attempts
        for _ in range(5):
            rate_limiter.record_failed_attempt(username, "192.168.1.3")
        
        # Check if account is locked
        is_locked = rate_limiter.is_account_locked(username)
        assert is_locked is True
        
        # Test unlock
        success = rate_limiter.unlock_account(username)
        assert success is True
        
        # Should no longer be locked
        is_locked = rate_limiter.is_account_locked(username)
        assert is_locked is False
    
    def test_password_policy_validation(self):
        """Test password policy validation."""
        # Test weak password
        result = rate_limiter.validate_password_policy("weak")
        assert result['valid'] is False
        assert len(result['errors']) > 0
        
        # Test strong password
        result = rate_limiter.validate_password_policy("StrongPass123!")
        assert result['valid'] is True
        assert len(result['errors']) == 0
    
    def test_password_history(self):
        """Test password history functionality."""
        username = "testuser_history"
        
        # Add password to history
        rate_limiter.add_password_to_history(username, "OldPass123!")
        
        # Test password in history
        result = rate_limiter.validate_password_policy("OldPass123!", username)
        assert result['valid'] is False
        assert "Password has been used recently" in result['errors']
        
        # Test new password
        result = rate_limiter.validate_password_policy("NewPass123!", username)
        assert result['valid'] is True


class TestIntegrityManagement:
    """Test OWASP A08: Data and Software Integrity."""
    
    def test_checksum_generation(self):
        """Test checksum generation."""
        data = "test data for integrity"
        checksum = integrity_manager.generate_checksum(data)
        
        assert len(checksum) == 64  # SHA-256 hex length
        assert checksum.isalnum()
    
    def test_data_integrity_validation(self):
        """Test data integrity validation."""
        data = "test data for integrity"
        checksum = integrity_manager.generate_checksum(data)
        
        # Valid data
        is_valid = integrity_manager.validate_data_integrity(data, checksum)
        assert is_valid is True
        
        # Invalid data
        is_valid = integrity_manager.validate_data_integrity("modified data", checksum)
        assert is_valid is False
    
    def test_digital_signature(self):
        """Test digital signature creation and verification."""
        data = "test data for signing"
        
        # Create signature
        signature = integrity_manager.create_digital_signature(data)
        assert signature is not None
        assert len(signature) > 0
        
        # Verify signature
        is_valid = integrity_manager.verify_digital_signature(data, signature)
        assert is_valid is True
        
        # Verify with modified data
        is_valid = integrity_manager.verify_digital_signature("modified data", signature)
        assert is_valid is False
    
    def test_file_integrity_monitoring(self):
        """Test file integrity monitoring."""
        # Create temporary file
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("test content")
            temp_file = f.name
        
        try:
            # Monitor file
            result = integrity_manager.monitor_file_integrity(temp_file)
            assert result['file_exists'] is True
            assert result['integrity_valid'] is True
            assert result['checksum'] is not None
            
            # Modify file
            with open(temp_file, 'w') as f:
                f.write("modified content")
            
            # Check again
            result = integrity_manager.monitor_file_integrity(temp_file)
            assert result['changes_detected'] is True
            
        finally:
            os.unlink(temp_file)
    
    def test_supply_chain_integrity(self):
        """Test supply chain integrity validation."""
        result = integrity_manager.validate_supply_chain_integrity()
        
        assert 'valid' in result
        assert 'checks' in result
        assert 'warnings' in result
        assert 'errors' in result


class TestAdvancedLogging:
    """Test OWASP A09: Advanced Logging and Monitoring."""
    
    def test_security_event_logging(self):
        """Test security event logging."""
        event_details = {
            'username': 'testuser',
            'source_ip': '192.168.1.100',
            'action': 'login_attempt'
        }
        
        # Log security event
        advanced_logger.log_security_event(
            SecurityEventType.LOGIN_SUCCESS,
            event_details,
            'info'
        )
        
        # Check if event was logged
        report = advanced_logger.get_security_report()
        assert report['metrics']['total_events'] > 0
    
    def test_anomaly_detection(self):
        """Test anomaly detection."""
        # Log multiple failed login events to trigger anomaly
        for _ in range(12):  # Exceed threshold
            advanced_logger.log_security_event(
                SecurityEventType.LOGIN_FAILURE,
                {'username': 'testuser', 'source_ip': '192.168.1.101'},
                'warning'
            )
        
        # Check for anomalies
        report = advanced_logger.get_security_report()
        assert report['metrics']['anomalies_detected'] > 0
    
    def test_incident_response(self):
        """Test incident response functionality."""
        # Log critical event to trigger incident response
        advanced_logger.log_security_event(
            SecurityEventType.INTEGRITY_VIOLATION,
            {
                'description': 'Test integrity violation',
                'severity': 'critical',
                'source_ip': '192.168.1.102'
            },
            'critical'
        )
        
        # Check if incident was created
        report = advanced_logger.get_security_report()
        assert report['recent_activity']['active_incidents'] > 0
    
    def test_log_integrity_validation(self):
        """Test log integrity validation."""
        result = advanced_logger.validate_log_integrity()
        
        assert 'valid_entries' in result
        assert 'invalid_entries' in result
        assert 'integrity_valid' in result


class TestSSRFProtection:
    """Test OWASP A10: SSRF Protection."""
    
    def test_url_validation(self):
        """Test URL validation for SSRF protection."""
        # Test valid URL
        result = ssrf_protection.validate_url("https://api.example.com/data")
        assert result['valid'] is True
        
        # Test suspicious URL
        result = ssrf_protection.validate_url("http://localhost:8080/admin")
        assert result['valid'] is False
        
        # Test file protocol
        result = ssrf_protection.validate_url("file:///etc/passwd")
        assert result['valid'] is False
    
    def test_ssrf_detection(self):
        """Test SSRF attempt detection."""
        # Test internal IP
        is_ssrf = ssrf_protection.detect_ssrf_attempt("http://127.0.0.1:3306")
        assert is_ssrf is True
        
        # Test localhost
        is_ssrf = ssrf_protection.detect_ssrf_attempt("http://localhost/admin")
        assert is_ssrf is True
        
        # Test valid external URL
        is_ssrf = ssrf_protection.detect_ssrf_attempt("https://api.example.com/data")
        assert is_ssrf is False
    
    def test_request_filtering(self):
        """Test request filtering for SSRF protection."""
        request_data = {
            'url': 'https://api.example.com/data',
            'callback': 'http://localhost:8080/callback',
            'data': 'normal data'
        }
        
        filtered_data = ssrf_protection.filter_request(request_data)
        
        assert filtered_data['url'] == 'https://api.example.com/data'
        assert filtered_data['callback'] == '[URL_FILTERED]'
        assert filtered_data['data'] == 'normal data'
    
    def test_domain_allowlist(self):
        """Test domain allowlist functionality."""
        # Test allowed domain
        is_allowed = ssrf_protection.is_allowed_domain("api.example.com")
        assert is_allowed is True
        
        # Test disallowed domain
        is_allowed = ssrf_protection.is_allowed_domain("malicious-site.com")
        assert is_allowed is False


class TestShoppingCart:
    """Test enhanced e-commerce shopping cart functionality."""
    
    def test_cart_creation(self):
        """Test shopping cart creation."""
        user_id = "testuser_cart"
        cart = ShoppingCart(user_id)
        
        assert cart.user_id == user_id
        assert len(cart.items) == 0
        assert cart.is_expired() is False
    
    def test_add_item_to_cart(self):
        """Test adding items to cart."""
        user_id = "testuser_add"
        cart = ShoppingCart(user_id)
        
        # Mock product data
        from app.core.storage import load_products, save_products
        products = load_products()
        
        # Create test product if none exist
        if not products:
            from app.models.product import Product
            test_product = Product("Test Product", 29.99, 10, "Test description")
            products[test_product.product_id] = test_product
            save_products(products)
        
        product_id = list(products.keys())[0]
        
        # Add item to cart
        success = cart.add_item(product_id, 2)
        assert success is True
        assert len(cart.items) == 1
        assert cart.items[product_id].quantity == 2
    
    def test_cart_summary(self):
        """Test cart summary calculation."""
        user_id = "testuser_summary"
        cart = ShoppingCart(user_id)
        
        # Mock product data
        from app.core.storage import load_products
        products = load_products()
        
        if products:
            product_id = list(products.keys())[0]
            cart.add_item(product_id, 1)
            
            summary = cart.get_cart_summary()
            assert 'subtotal' in summary
            assert 'shipping_cost' in summary
            assert 'tax_amount' in summary
            assert 'total' in summary
            assert summary['item_count'] == 1
    
    def test_cart_expiration(self):
        """Test cart expiration functionality."""
        user_id = "testuser_expire"
        cart = ShoppingCart(user_id)
        
        # Manually expire cart
        cart.expires_at = datetime.utcnow() - timedelta(days=1)
        
        assert cart.is_expired() is True
        
        # Refresh expiration
        cart.refresh_expiration()
        assert cart.is_expired() is False


class TestOrderManagement:
    """Test enhanced e-commerce order management."""
    
    def test_order_creation(self):
        """Test order creation from cart."""
        user_id = "testuser_order"
        
        # Create cart with items
        cart = ShoppingCart(user_id)
        
        # Mock product data
        from app.core.storage import load_products
        products = load_products()
        
        if products:
            product_id = list(products.keys())[0]
            cart.add_item(product_id, 1)
            
            # Set required order information
            cart.set_shipping_address({
                'street': '123 Test St',
                'city': 'Test City',
                'state': 'TS',
                'zip_code': '12345',
                'country': 'Test Country'
            })
            cart.set_payment_method('credit_card')
            
            # Create order
            order = order_manager.create_order(user_id, cart)
            
            assert order is not None
            assert order.user_id == user_id
            assert order.status == OrderStatus.PENDING
            assert order.payment_status == PaymentStatus.PENDING
    
    def test_order_status_updates(self):
        """Test order status updates."""
        user_id = "testuser_status"
        
        # Create test order
        cart = ShoppingCart(user_id)
        from app.core.storage import load_products
        products = load_products()
        
        if products:
            product_id = list(products.keys())[0]
            cart.add_item(product_id, 1)
            cart.set_shipping_address({
                'street': '123 Test St',
                'city': 'Test City',
                'state': 'TS',
                'zip_code': '12345',
                'country': 'Test Country'
            })
            cart.set_payment_method('credit_card')
            
            order = order_manager.create_order(user_id, cart)
            
            if order:
                # Update order status
                success = order_manager.update_order_status(
                    order.order_id, 
                    OrderStatus.CONFIRMED,
                    "Payment received"
                )
                assert success is True
                
                # Check updated order
                updated_order = order_manager.get_order(order.order_id)
                assert updated_order.status == OrderStatus.CONFIRMED
    
    def test_fraud_detection(self):
        """Test fraud detection in orders."""
        user_id = "testuser_fraud"
        
        # Create high-value order to trigger fraud detection
        cart = ShoppingCart(user_id)
        
        # Mock high-value product
        from app.models.product import Product
        high_value_product = Product("Expensive Item", 1500.00, 1, "High value item")
        
        # Add to cart
        cart.add_item(high_value_product.product_id, 1)
        cart.set_shipping_address({
            'street': '123 Test St',
            'city': 'Test City',
            'state': 'TS',
            'zip_code': '12345',
            'country': 'Test Country'
        })
        cart.set_payment_method('credit_card')
        
        # Create order
        order = order_manager.create_order(user_id, cart)
        
        if order:
            assert order.fraud_score > 0
            assert len(order.security_flags) > 0
    
    def test_order_statistics(self):
        """Test order statistics generation."""
        stats = order_manager.get_order_statistics()
        
        assert 'total_orders' in stats
        assert 'completed_orders' in stats
        assert 'cancelled_orders' in stats
        assert 'total_revenue' in stats
        assert 'status_distribution' in stats


class TestSecurityIntegration:
    """Test integration of all security features."""
    
    def test_complete_security_workflow(self):
        """Test complete security workflow with all OWASP A01-A10 features."""
        # 1. Test rate limiting (A07)
        rate_limit_result = rate_limiter.check_rate_limit("192.168.1.200", "login")
        assert rate_limit_result is True
        
        # 2. Test integrity management (A08)
        test_data = "integration test data"
        checksum = integrity_manager.generate_checksum(test_data)
        integrity_result = integrity_manager.validate_data_integrity(test_data, checksum)
        assert integrity_result is True
        
        # 3. Test advanced logging (A09)
        advanced_logger.log_security_event(
            SecurityEventType.LOGIN_SUCCESS,
            {'username': 'integration_test', 'source_ip': '192.168.1.201'},
            'info'
        )
        
        # 4. Test SSRF protection (A10)
        ssrf_result = ssrf_protection.validate_url("https://api.example.com/data")
        assert ssrf_result['valid'] is True
        
        # 5. Test e-commerce functionality
        cart = ShoppingCart("integration_test_user")
        assert cart is not None
        
        # 6. Verify all systems are working together
        report = advanced_logger.get_security_report()
        assert report['metrics']['total_events'] > 0
        
        integrity_stats = integrity_manager.get_integrity_statistics()
        assert integrity_stats['total_monitored_files'] > 0
        
        ssrf_stats = ssrf_protection.get_ssrf_statistics()
        assert ssrf_stats['allowed_domains'] > 0
    
    def test_security_event_correlation(self):
        """Test correlation between different security events."""
        # Create multiple security events
        advanced_logger.log_security_event(
            SecurityEventType.LOGIN_FAILURE,
            {'username': 'testuser', 'source_ip': '192.168.1.202'},
            'warning'
        )
        
        advanced_logger.log_security_event(
            SecurityEventType.RATE_LIMIT_EXCEEDED,
            {'ip_address': '192.168.1.202', 'action': 'login'},
            'warning'
        )
        
        # Check for correlation in security report
        report = advanced_logger.get_security_report()
        assert report['metrics']['security_incidents'] > 0
        
        # Check for anomalies
        anomalies = report['anomalies']
        assert len(anomalies) > 0
    
    def test_comprehensive_security_validation(self):
        """Test comprehensive security validation across all systems."""
        # Test all security managers are functional
        assert rate_limiter is not None
        assert integrity_manager is not None
        assert advanced_logger is not None
        assert ssrf_protection is not None
        
        # Test all managers have required methods
        assert hasattr(rate_limiter, 'check_rate_limit')
        assert hasattr(integrity_manager, 'generate_checksum')
        assert hasattr(advanced_logger, 'log_security_event')
        assert hasattr(ssrf_protection, 'validate_url')
        
        # Test all managers can generate statistics
        rate_stats = rate_limiter.get_rate_limit_stats()
        integrity_stats = integrity_manager.get_integrity_statistics()
        security_report = advanced_logger.get_security_report()
        ssrf_stats = ssrf_protection.get_ssrf_statistics()
        
        assert isinstance(rate_stats, dict)
        assert isinstance(integrity_stats, dict)
        assert isinstance(security_report, dict)
        assert isinstance(ssrf_stats, dict)


if __name__ == '__main__':
    pytest.main([__file__]) 