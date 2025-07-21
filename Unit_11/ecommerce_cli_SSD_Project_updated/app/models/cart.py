"""
Filename: cart.py
Author: Mobeen Ali
Date: July 2025

Purpose:
--------
Implements shopping cart functionality for the Secure CLI E-Commerce Application.
Provides comprehensive cart management, item tracking, pricing calculations,
and security features for e-commerce operations.

Features:
---------
- Shopping cart management
- Item quantity tracking
- Price calculations and discounts
- Cart persistence and security
- Inventory validation
- Tax calculations
- Shipping options
- Cart expiration
"""

import json
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from decimal import Decimal, ROUND_HALF_UP
from app.core.logger import Logger
from app.models.product import Product

class CartItem:
    """Represents an item in the shopping cart."""
    
    def __init__(self, product_id: str, quantity: int = 1):
        self.product_id = product_id
        self.quantity = quantity
        self.added_at = datetime.utcnow()
        self.last_updated = datetime.utcnow()
    
    def to_dict(self) -> dict:
        """Convert cart item to dictionary."""
        return {
            'product_id': self.product_id,
            'quantity': self.quantity,
            'added_at': self.added_at.isoformat(),
            'last_updated': self.last_updated.isoformat()
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'CartItem':
        """Create cart item from dictionary."""
        item = cls(data['product_id'], data['quantity'])
        item.added_at = datetime.fromisoformat(data['added_at'])
        item.last_updated = datetime.fromisoformat(data['last_updated'])
        return item

class ShoppingCart:
    """Shopping cart with comprehensive e-commerce features."""
    
    def __init__(self, user_id: str):
        self.user_id = user_id
        self.cart_file = f"carts/{user_id}_cart.json"
        self.items: Dict[str, CartItem] = {}
        self.coupons: List[str] = []
        self.shipping_address: Optional[dict] = None
        self.payment_method: Optional[str] = None
        self.created_at = datetime.utcnow()
        self.last_updated = datetime.utcnow()
        self.expires_at = datetime.utcnow() + timedelta(days=30)
        
        # Tax and shipping configuration
        self.tax_rate = Decimal('0.08')  # 8% tax rate
        self.shipping_options = {
            'standard': {'name': 'Standard Shipping', 'cost': Decimal('5.99'), 'days': 5},
            'express': {'name': 'Express Shipping', 'cost': Decimal('12.99'), 'days': 2},
            'overnight': {'name': 'Overnight Shipping', 'cost': Decimal('24.99'), 'days': 1}
        }
        self.selected_shipping = 'standard'
        
        # Load existing cart
        self._load_cart()
    
    def _load_cart(self):
        """Load cart from file."""
        try:
            if os.path.exists(self.cart_file):
                with open(self.cart_file, 'r') as f:
                    data = json.load(f)
                    
                    # Load items
                    self.items = {
                        item_id: CartItem.from_dict(item_data)
                        for item_id, item_data in data.get('items', {}).items()
                    }
                    
                    # Load other data
                    self.coupons = data.get('coupons', [])
                    self.shipping_address = data.get('shipping_address')
                    self.payment_method = data.get('payment_method')
                    self.selected_shipping = data.get('selected_shipping', 'standard')
                    
                    # Load timestamps
                    if 'created_at' in data:
                        self.created_at = datetime.fromisoformat(data['created_at'])
                    if 'last_updated' in data:
                        self.last_updated = datetime.fromisoformat(data['last_updated'])
                    if 'expires_at' in data:
                        self.expires_at = datetime.fromisoformat(data['expires_at'])
                    
        except Exception as e:
            Logger.error(f"Failed to load cart for user {self.user_id}: {str(e)}")
    
    def _save_cart(self):
        """Save cart to file."""
        try:
            # Ensure carts directory exists
            os.makedirs(os.path.dirname(self.cart_file), exist_ok=True)
            
            data = {
                'user_id': self.user_id,
                'items': {
                    item_id: item.to_dict()
                    for item_id, item in self.items.items()
                },
                'coupons': self.coupons,
                'shipping_address': self.shipping_address,
                'payment_method': self.payment_method,
                'selected_shipping': self.selected_shipping,
                'created_at': self.created_at.isoformat(),
                'last_updated': self.last_updated.isoformat(),
                'expires_at': self.expires_at.isoformat()
            }
            
            with open(self.cart_file, 'w') as f:
                json.dump(data, f, indent=2)
                
        except Exception as e:
            Logger.error(f"Failed to save cart for user {self.user_id}: {str(e)}")
    
    def add_item(self, product_id: str, quantity: int = 1) -> bool:
        """
        Add item to cart.
        
        Args:
            product_id (str): Product ID to add
            quantity (int): Quantity to add
            
        Returns:
            bool: True if added successfully, False otherwise
        """
        try:
            # Validate product exists
            if not self._validate_product(product_id):
                Logger.warning(f"Product {product_id} not found or out of stock")
                return False
            
            # Check if item already exists
            if product_id in self.items:
                self.items[product_id].quantity += quantity
                self.items[product_id].last_updated = datetime.utcnow()
            else:
                self.items[product_id] = CartItem(product_id, quantity)
            
            self.last_updated = datetime.utcnow()
            self._save_cart()
            
            Logger.info(f"Added {quantity} of product {product_id} to cart for user {self.user_id}")
            return True
            
        except Exception as e:
            Logger.error(f"Failed to add item to cart: {str(e)}")
            return False
    
    def remove_item(self, product_id: str) -> bool:
        """
        Remove item from cart.
        
        Args:
            product_id (str): Product ID to remove
            
        Returns:
            bool: True if removed successfully, False otherwise
        """
        try:
            if product_id in self.items:
                del self.items[product_id]
                self.last_updated = datetime.utcnow()
                self._save_cart()
                
                Logger.info(f"Removed product {product_id} from cart for user {self.user_id}")
                return True
            
            return False
            
        except Exception as e:
            Logger.error(f"Failed to remove item from cart: {str(e)}")
            return False
    
    def update_quantity(self, product_id: str, quantity: int) -> bool:
        """
        Update item quantity in cart.
        
        Args:
            product_id (str): Product ID to update
            quantity (int): New quantity
            
        Returns:
            bool: True if updated successfully, False otherwise
        """
        try:
            if product_id in self.items:
                if quantity <= 0:
                    return self.remove_item(product_id)
                
                # Validate stock availability
                if not self._validate_stock(product_id, quantity):
                    Logger.warning(f"Insufficient stock for product {product_id}")
                    return False
                
                self.items[product_id].quantity = quantity
                self.items[product_id].last_updated = datetime.utcnow()
                self.last_updated = datetime.utcnow()
                self._save_cart()
                
                Logger.info(f"Updated quantity for product {product_id} to {quantity}")
                return True
            
            return False
            
        except Exception as e:
            Logger.error(f"Failed to update quantity: {str(e)}")
            return False
    
    def clear_cart(self) -> bool:
        """
        Clear all items from cart.
        
        Returns:
            bool: True if cleared successfully, False otherwise
        """
        try:
            self.items.clear()
            self.coupons.clear()
            self.shipping_address = None
            self.payment_method = None
            self.selected_shipping = 'standard'
            self.last_updated = datetime.utcnow()
            self._save_cart()
            
            Logger.info(f"Cleared cart for user {self.user_id}")
            return True
            
        except Exception as e:
            Logger.error(f"Failed to clear cart: {str(e)}")
            return False
    
    def get_cart_summary(self) -> dict:
        """
        Get cart summary with pricing details.
        
        Returns:
            dict: Cart summary with items, totals, and pricing
        """
        try:
            subtotal = Decimal('0.00')
            items_summary = []
            
            for product_id, item in self.items.items():
                product = self._get_product(product_id)
                if product:
                    item_total = Decimal(str(product.price)) * item.quantity
                    subtotal += item_total
                    
                    items_summary.append({
                        'product_id': product_id,
                        'name': product.name,
                        'price': float(product.price),
                        'quantity': item.quantity,
                        'item_total': float(item_total),
                        'available': product.quantity >= item.quantity
                    })
            
            # Calculate shipping
            shipping_cost = self.shipping_options[self.selected_shipping]['cost']
            
            # Calculate tax
            tax_amount = subtotal * self.tax_rate
            
            # Calculate total
            total = subtotal + shipping_cost + tax_amount
            
            return {
                'user_id': self.user_id,
                'items': items_summary,
                'subtotal': float(subtotal),
                'shipping_cost': float(shipping_cost),
                'tax_amount': float(tax_amount),
                'total': float(total),
                'item_count': len(self.items),
                'total_quantity': sum(item.quantity for item in self.items.values()),
                'shipping_option': self.selected_shipping,
                'shipping_address': self.shipping_address,
                'payment_method': self.payment_method,
                'coupons': self.coupons,
                'last_updated': self.last_updated.isoformat(),
                'expires_at': self.expires_at.isoformat()
            }
            
        except Exception as e:
            Logger.error(f"Failed to get cart summary: {str(e)}")
            return {}
    
    def set_shipping_address(self, address: dict) -> bool:
        """
        Set shipping address.
        
        Args:
            address (dict): Shipping address information
            
        Returns:
            bool: True if set successfully, False otherwise
        """
        try:
            required_fields = ['street', 'city', 'state', 'zip_code', 'country']
            for field in required_fields:
                if field not in address or not address[field]:
                    Logger.warning(f"Missing required shipping address field: {field}")
                    return False
            
            self.shipping_address = address
            self.last_updated = datetime.utcnow()
            self._save_cart()
            
            Logger.info(f"Set shipping address for user {self.user_id}")
            return True
            
        except Exception as e:
            Logger.error(f"Failed to set shipping address: {str(e)}")
            return False
    
    def set_payment_method(self, payment_method: str) -> bool:
        """
        Set payment method.
        
        Args:
            payment_method (str): Payment method (credit_card, paypal, etc.)
            
        Returns:
            bool: True if set successfully, False otherwise
        """
        try:
            valid_methods = ['credit_card', 'paypal', 'bank_transfer']
            if payment_method not in valid_methods:
                Logger.warning(f"Invalid payment method: {payment_method}")
                return False
            
            self.payment_method = payment_method
            self.last_updated = datetime.utcnow()
            self._save_cart()
            
            Logger.info(f"Set payment method {payment_method} for user {self.user_id}")
            return True
            
        except Exception as e:
            Logger.error(f"Failed to set payment method: {str(e)}")
            return False
    
    def set_shipping_option(self, option: str) -> bool:
        """
        Set shipping option.
        
        Args:
            option (str): Shipping option (standard, express, overnight)
            
        Returns:
            bool: True if set successfully, False otherwise
        """
        try:
            if option not in self.shipping_options:
                Logger.warning(f"Invalid shipping option: {option}")
                return False
            
            self.selected_shipping = option
            self.last_updated = datetime.utcnow()
            self._save_cart()
            
            Logger.info(f"Set shipping option {option} for user {self.user_id}")
            return True
            
        except Exception as e:
            Logger.error(f"Failed to set shipping option: {str(e)}")
            return False
    
    def add_coupon(self, coupon_code: str) -> bool:
        """
        Add coupon to cart.
        
        Args:
            coupon_code (str): Coupon code to add
            
        Returns:
            bool: True if added successfully, False otherwise
        """
        try:
            # Validate coupon (simplified validation)
            if not self._validate_coupon(coupon_code):
                Logger.warning(f"Invalid coupon code: {coupon_code}")
                return False
            
            if coupon_code not in self.coupons:
                self.coupons.append(coupon_code)
                self.last_updated = datetime.utcnow()
                self._save_cart()
                
                Logger.info(f"Added coupon {coupon_code} to cart for user {self.user_id}")
                return True
            
            return False
            
        except Exception as e:
            Logger.error(f"Failed to add coupon: {str(e)}")
            return False
    
    def remove_coupon(self, coupon_code: str) -> bool:
        """
        Remove coupon from cart.
        
        Args:
            coupon_code (str): Coupon code to remove
            
        Returns:
            bool: True if removed successfully, False otherwise
        """
        try:
            if coupon_code in self.coupons:
                self.coupons.remove(coupon_code)
                self.last_updated = datetime.utcnow()
                self._save_cart()
                
                Logger.info(f"Removed coupon {coupon_code} from cart for user {self.user_id}")
                return True
            
            return False
            
        except Exception as e:
            Logger.error(f"Failed to remove coupon: {str(e)}")
            return False
    
    def is_expired(self) -> bool:
        """
        Check if cart has expired.
        
        Returns:
            bool: True if cart is expired, False otherwise
        """
        return datetime.utcnow() > self.expires_at
    
    def refresh_expiration(self):
        """Refresh cart expiration date."""
        self.expires_at = datetime.utcnow() + timedelta(days=30)
        self._save_cart()
    
    def _validate_product(self, product_id: str) -> bool:
        """Validate that product exists and is in stock."""
        product = self._get_product(product_id)
        return product is not None and product.quantity > 0
    
    def _validate_stock(self, product_id: str, quantity: int) -> bool:
        """Validate stock availability for quantity."""
        product = self._get_product(product_id)
        return product is not None and product.quantity >= quantity
    
    def _get_product(self, product_id: str) -> Optional[Product]:
        """Get product by ID."""
        try:
            from app.core.auth import load_products
            products = load_products()
            product_data = products.get(product_id)
            
            if product_data:
                # Convert dictionary to Product object
                return Product(
                    name=product_data['name'],
                    price=product_data['price'],
                    quantity=product_data['quantity'],  # Use 'quantity' to match Product constructor
                    description=product_data['description'],
                    product_id=product_id  # Pass the product_id explicitly
                )
            return None
        except Exception as e:
            Logger.error(f"Failed to get product {product_id}: {str(e)}")
            return None
    
    def _validate_coupon(self, coupon_code: str) -> bool:
        """Validate coupon code (simplified implementation)."""
        # In a real implementation, this would check against a coupon database
        valid_coupons = ['SAVE10', 'WELCOME20', 'FREESHIP']
        return coupon_code.upper() in valid_coupons
    
    def get_cart_statistics(self) -> dict:
        """Get cart statistics."""
        summary = self.get_cart_summary()
        
        stats = {
            'user_id': self.user_id,
            'item_count': len(self.items),
            'total_quantity': sum(item.quantity for item in self.items.values()),
            'subtotal': summary.get('subtotal', 0.0),
            'total': summary.get('total', 0.0),
            'has_shipping_address': self.shipping_address is not None,
            'has_payment_method': self.payment_method is not None,
            'coupon_count': len(self.coupons),
            'is_expired': self.is_expired(),
            'created_at': self.created_at.isoformat(),
            'last_updated': self.last_updated.isoformat(),
            'expires_at': self.expires_at.isoformat()
        }
        
        return stats 