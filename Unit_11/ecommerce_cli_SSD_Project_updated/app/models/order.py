"""
Filename: order.py
Author: Mobeen Ali
Date: July 2025

Purpose:
--------
Implements order management for the Secure CLI E-Commerce Application.
Provides comprehensive order processing, payment handling, and fulfillment
tracking with security features for e-commerce operations.

Features:
---------
- Order creation and management
- Payment processing and validation
- Order status tracking
- Inventory management
- Shipping and fulfillment
- Order history and reporting
- Security and fraud detection
- Refund and return processing
"""

import json
import os
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from decimal import Decimal
from enum import Enum
from app.core.logger import Logger
from app.models.cart import ShoppingCart

class OrderStatus(Enum):
    """Order status enumeration."""
    PENDING = "pending"
    CONFIRMED = "confirmed"
    PROCESSING = "processing"
    SHIPPED = "shipped"
    DELIVERED = "delivered"
    CANCELLED = "cancelled"
    REFUNDED = "refunded"
    RETURNED = "returned"

class PaymentStatus(Enum):
    """Payment status enumeration."""
    PENDING = "pending"
    AUTHORIZED = "authorized"
    PAID = "paid"
    FAILED = "failed"
    REFUNDED = "refunded"
    PARTIALLY_REFUNDED = "partially_refunded"

class Order:
    """Represents an order in the e-commerce system."""
    
    def __init__(self, order_id: str, user_id: str, cart: ShoppingCart):
        self.order_id = order_id
        self.user_id = user_id
        self.cart = cart
        self.status = OrderStatus.PENDING
        self.payment_status = PaymentStatus.PENDING
        self.created_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()
        self.estimated_delivery = None
        self.tracking_number = None
        self.notes = []
        self.payment_transaction_id = None
        
        # Order details
        self.items = []
        self.subtotal = Decimal('0.00')
        self.shipping_cost = Decimal('0.00')
        self.tax_amount = Decimal('0.00')
        self.total = Decimal('0.00')
        self.discount_amount = Decimal('0.00')
        
        # Security and fraud detection
        self.fraud_score = 0
        self.security_flags = []
        self.ip_address = None
        self.user_agent = None
        
        # Initialize order from cart
        self._initialize_from_cart()
    
    def _initialize_from_cart(self):
        """Initialize order details from shopping cart."""
        cart_summary = self.cart.get_cart_summary()
        
        self.items = cart_summary.get('items', [])
        self.subtotal = Decimal(str(cart_summary.get('subtotal', 0)))
        self.shipping_cost = Decimal(str(cart_summary.get('shipping_cost', 0)))
        self.tax_amount = Decimal(str(cart_summary.get('tax_amount', 0)))
        self.total = Decimal(str(cart_summary.get('total', 0)))
        
        # Calculate discount from coupons
        self.discount_amount = self._calculate_discount()
        self.total -= self.discount_amount
    
    def _calculate_discount(self) -> Decimal:
        """Calculate discount amount from coupons."""
        discount = Decimal('0.00')
        
        for coupon in self.cart.coupons:
            if coupon.upper() == 'SAVE10':
                discount += self.subtotal * Decimal('0.10')
            elif coupon.upper() == 'WELCOME20':
                discount += self.subtotal * Decimal('0.20')
            elif coupon.upper() == 'FREESHIP':
                discount += self.shipping_cost
        
        return discount
    
    def to_dict(self) -> dict:
        """Convert order to dictionary."""
        return {
            'order_id': self.order_id,
            'user_id': self.user_id,
            'status': self.status.value,
            'payment_status': self.payment_status.value,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'estimated_delivery': self.estimated_delivery.isoformat() if self.estimated_delivery else None,
            'tracking_number': self.tracking_number,
            'items': self.items,
            'subtotal': float(self.subtotal),
            'shipping_cost': float(self.shipping_cost),
            'tax_amount': float(self.tax_amount),
            'discount_amount': float(self.discount_amount),
            'total': float(self.total),
            'shipping_address': self.cart.shipping_address,
            'payment_method': self.cart.payment_method,
            'payment_transaction_id': self.payment_transaction_id,
            'fraud_score': self.fraud_score,
            'security_flags': self.security_flags,
            'notes': self.notes
        }
    
    @classmethod
    def from_dict(cls, data: dict, cart: ShoppingCart) -> 'Order':
        """Create order from dictionary."""
        order = cls(data['order_id'], data['user_id'], cart)
        order.status = OrderStatus(data['status'])
        order.payment_status = PaymentStatus(data['payment_status'])
        order.created_at = datetime.fromisoformat(data['created_at'])
        order.updated_at = datetime.fromisoformat(data['updated_at'])
        order.estimated_delivery = datetime.fromisoformat(data['estimated_delivery']) if data.get('estimated_delivery') else None
        order.tracking_number = data.get('tracking_number')
        order.items = data.get('items', [])
        order.subtotal = Decimal(str(data.get('subtotal', 0)))
        order.shipping_cost = Decimal(str(data.get('shipping_cost', 0)))
        order.tax_amount = Decimal(str(data.get('tax_amount', 0)))
        order.discount_amount = Decimal(str(data.get('discount_amount', 0)))
        order.total = Decimal(str(data.get('total', 0)))
        order.payment_transaction_id = data.get('payment_transaction_id')
        order.fraud_score = data.get('fraud_score', 0)
        order.security_flags = data.get('security_flags', [])
        order.notes = data.get('notes', [])
        return order

class OrderManager:
    """Manages order processing and fulfillment."""
    
    def __init__(self):
        self.orders_file = "data/orders.json"
        self.orders: Dict[str, Order] = {}
        self.order_counter = 0
        
        # Load existing orders
        self._load_orders()
    
    def _load_orders(self):
        """Load orders from file."""
        try:
            if os.path.exists(self.orders_file):
                with open(self.orders_file, 'r') as f:
                    data = json.load(f)
                    
                    for order_id, order_data in data.items():
                        # Create cart for order
                        cart = ShoppingCart(order_data['user_id'])
                        order = Order.from_dict(order_data, cart)
                        self.orders[order_id] = order
                        
                        # Update counter
                        order_num = int(order_id.split('_')[1])
                        if order_num > self.order_counter:
                            self.order_counter = order_num
                            
        except Exception as e:
            Logger.error(f"Failed to load orders: {str(e)}")
    
    def _save_orders(self):
        """Save orders to file."""
        try:
            data = {
                order_id: order.to_dict()
                for order_id, order in self.orders.items()
            }
            
            with open(self.orders_file, 'w') as f:
                json.dump(data, f, indent=2)
                
        except Exception as e:
            Logger.error(f"Failed to save orders: {str(e)}")
    
    def create_order(self, user_id: str, cart: ShoppingCart, payment_info: dict = None) -> Optional[Order]:
        """
        Create a new order from shopping cart.
        
        Args:
            user_id (str): User ID
            cart (ShoppingCart): Shopping cart
            payment_info (dict): Payment information
            
        Returns:
            Order: Created order or None if failed
        """
        try:
            # Validate cart
            if not cart.items:
                Logger.warning("Cannot create order from empty cart")
                return None
            
            # Generate order ID
            self.order_counter += 1
            order_id = f"ORD_{self.order_counter:06d}"
            
            # Create order
            order = Order(order_id, user_id, cart)
            
            # Set payment information
            if payment_info:
                order.payment_transaction_id = payment_info.get('transaction_id')
                order.ip_address = payment_info.get('ip_address')
                order.user_agent = payment_info.get('user_agent')
            
            # Fraud detection
            self._detect_fraud(order)
            
            # Save order
            self.orders[order_id] = order
            self._save_orders()
            
            # Clear cart after successful order creation
            cart.clear_cart()
            
            Logger.info(f"Created order {order_id} for user {user_id}")
            return order
            
        except Exception as e:
            Logger.error(f"Failed to create order: {str(e)}")
            return None
    
    def get_order(self, order_id: str) -> Optional[Order]:
        """
        Get order by ID.
        
        Args:
            order_id (str): Order ID
            
        Returns:
            Order: Order object or None if not found
        """
        return self.orders.get(order_id)
    
    def get_user_orders(self, user_id: str) -> List[Order]:
        """
        Get all orders for a user.
        
        Args:
            user_id (str): User ID
            
        Returns:
            List[Order]: List of user orders
        """
        return [order for order in self.orders.values() if order.user_id == user_id]
    
    def update_order_status(self, order_id: str, status: OrderStatus, notes: str = None) -> bool:
        """
        Update order status.
        
        Args:
            order_id (str): Order ID
            status (OrderStatus): New status
            notes (str): Optional notes
            
        Returns:
            bool: True if updated successfully, False otherwise
        """
        try:
            order = self.get_order(order_id)
            if not order:
                Logger.warning(f"Order {order_id} not found")
                return False
            
            old_status = order.status
            order.status = status
            order.updated_at = datetime.utcnow()
            
            if notes:
                order.notes.append({
                    'timestamp': datetime.utcnow().isoformat(),
                    'status': status.value,
                    'note': notes
                })
            
            # Handle status-specific actions
            if status == OrderStatus.CONFIRMED:
                self._process_payment(order)
            elif status == OrderStatus.SHIPPED:
                self._generate_tracking(order)
            elif status == OrderStatus.DELIVERED:
                self._complete_order(order)
            
            self._save_orders()
            
            Logger.info(f"Updated order {order_id} status from {old_status.value} to {status.value}")
            return True
            
        except Exception as e:
            Logger.error(f"Failed to update order status: {str(e)}")
            return False
    
    def update_payment_status(self, order_id: str, payment_status: PaymentStatus, transaction_id: str = None) -> bool:
        """
        Update payment status.
        
        Args:
            order_id (str): Order ID
            payment_status (PaymentStatus): New payment status
            transaction_id (str): Payment transaction ID
            
        Returns:
            bool: True if updated successfully, False otherwise
        """
        try:
            order = self.get_order(order_id)
            if not order:
                return False
            
            order.payment_status = payment_status
            order.updated_at = datetime.utcnow()
            
            if transaction_id:
                order.payment_transaction_id = transaction_id
            
            # Update order status based on payment
            if payment_status == PaymentStatus.PAID:
                self.update_order_status(order_id, OrderStatus.CONFIRMED, "Payment received")
            elif payment_status == PaymentStatus.FAILED:
                self.update_order_status(order_id, OrderStatus.CANCELLED, "Payment failed")
            
            self._save_orders()
            
            Logger.info(f"Updated payment status for order {order_id} to {payment_status.value}")
            return True
            
        except Exception as e:
            Logger.error(f"Failed to update payment status: {str(e)}")
            return False
    
    def _detect_fraud(self, order: Order):
        """Detect potential fraud in order."""
        fraud_score = 0
        security_flags = []
        
        # Check for high-value orders
        if order.total > Decimal('1000.00'):
            fraud_score += 20
            security_flags.append("high_value_order")
        
        # Check for rapid orders
        user_orders = self.get_user_orders(order.user_id)
        recent_orders = [
            o for o in user_orders
            if datetime.utcnow() - o.created_at < timedelta(hours=1)
        ]
        
        if len(recent_orders) > 3:
            fraud_score += 30
            security_flags.append("rapid_ordering")
        
        # Check for unusual shipping address
        if order.cart.shipping_address:
            # Add logic for address validation
            pass
        
        # Check for suspicious payment patterns
        if order.payment_transaction_id:
            # Add logic for payment pattern analysis
            pass
        
        order.fraud_score = fraud_score
        order.security_flags = security_flags
        
        if fraud_score > 50:
            Logger.warning(f"High fraud score detected for order {order.order_id}: {fraud_score}")
    
    def _process_payment(self, order: Order):
        """Process payment for order."""
        # Simulate payment processing
        if order.payment_status == PaymentStatus.PENDING:
            # In a real implementation, this would integrate with payment gateway
            order.payment_status = PaymentStatus.PAID
            order.payment_transaction_id = f"TXN_{uuid.uuid4().hex[:8].upper()}"
            
            Logger.info(f"Payment processed for order {order.order_id}")
    
    def _generate_tracking(self, order: Order):
        """Generate tracking number for shipped order."""
        if not order.tracking_number:
            order.tracking_number = f"TRK_{uuid.uuid4().hex[:12].upper()}"
            
            # Calculate estimated delivery
            shipping_days = order.cart.shipping_options[order.cart.selected_shipping]['days']
            order.estimated_delivery = datetime.utcnow() + timedelta(days=shipping_days)
            
            Logger.info(f"Generated tracking number {order.tracking_number} for order {order.order_id}")
    
    def _complete_order(self, order: Order):
        """Complete order processing."""
        # Update inventory
        self._update_inventory(order)
        
        # Generate order completion notification
        Logger.info(f"Order {order.order_id} completed successfully")
    
    def _update_inventory(self, order: Order):
        """Update inventory for completed order."""
        try:
            from app.core.storage import load_products, save_products
            
            products = load_products()
            
            for item in order.items:
                product_id = item['product_id']
                quantity = item['quantity']
                
                if product_id in products:
                    product = products[product_id]
                    product.stock -= quantity
                    
                    if product.stock < 0:
                        Logger.warning(f"Negative stock detected for product {product_id}")
                        product.stock = 0
            
            save_products(products)
            
        except Exception as e:
            Logger.error(f"Failed to update inventory: {str(e)}")
    
    def cancel_order(self, order_id: str, reason: str = None) -> bool:
        """
        Cancel an order.
        
        Args:
            order_id (str): Order ID
            reason (str): Cancellation reason
            
        Returns:
            bool: True if cancelled successfully, False otherwise
        """
        try:
            order = self.get_order(order_id)
            if not order:
                return False
            
            # Check if order can be cancelled
            if order.status in [OrderStatus.SHIPPED, OrderStatus.DELIVERED]:
                Logger.warning(f"Cannot cancel order {order_id} - already shipped")
                return False
            
            # Update status
            self.update_order_status(order_id, OrderStatus.CANCELLED, f"Order cancelled: {reason}")
            
            # Process refund if payment was made
            if order.payment_status == PaymentStatus.PAID:
                self.update_payment_status(order_id, PaymentStatus.REFUNDED)
            
            Logger.info(f"Order {order_id} cancelled: {reason}")
            return True
            
        except Exception as e:
            Logger.error(f"Failed to cancel order: {str(e)}")
            return False
    
    def get_order_statistics(self) -> dict:
        """Get order statistics."""
        total_orders = len(self.orders)
        completed_orders = len([o for o in self.orders.values() if o.status == OrderStatus.DELIVERED])
        cancelled_orders = len([o for o in self.orders.values() if o.status == OrderStatus.CANCELLED])
        
        total_revenue = sum(order.total for order in self.orders.values() if order.status == OrderStatus.DELIVERED)
        
        # Status distribution
        status_counts = {}
        for status in OrderStatus:
            status_counts[status.value] = len([o for o in self.orders.values() if o.status == status])
        
        # Fraud statistics
        high_fraud_orders = len([o for o in self.orders.values() if o.fraud_score > 50])
        
        return {
            'total_orders': total_orders,
            'completed_orders': completed_orders,
            'cancelled_orders': cancelled_orders,
            'total_revenue': float(total_revenue),
            'status_distribution': status_counts,
            'high_fraud_orders': high_fraud_orders,
            'average_order_value': float(total_revenue / completed_orders) if completed_orders > 0 else 0.0
        }
    
    def search_orders(self, criteria: dict) -> List[Order]:
        """
        Search orders based on criteria.
        
        Args:
            criteria (dict): Search criteria
            
        Returns:
            List[Order]: Matching orders
        """
        results = []
        
        for order in self.orders.values():
            match = True
            
            # Filter by status
            if 'status' in criteria and order.status.value != criteria['status']:
                match = False
            
            # Filter by user
            if 'user_id' in criteria and order.user_id != criteria['user_id']:
                match = False
            
            # Filter by date range
            if 'start_date' in criteria:
                start_date = datetime.fromisoformat(criteria['start_date'])
                if order.created_at < start_date:
                    match = False
            
            if 'end_date' in criteria:
                end_date = datetime.fromisoformat(criteria['end_date'])
                if order.created_at > end_date:
                    match = False
            
            # Filter by amount range
            if 'min_amount' in criteria and order.total < Decimal(str(criteria['min_amount'])):
                match = False
            
            if 'max_amount' in criteria and order.total > Decimal(str(criteria['max_amount'])):
                match = False
            
            if match:
                results.append(order)
        
        return results

# Global order manager instance
order_manager = OrderManager() 