"""
Filename: product.py
Author: Mobeen Ali
Date: July 2025

Purpose:
--------
Defines the Product class used in the Secure CLI E-Commerce Application.
Each product is uniquely identified and supports serialization to/from dictionary format
for use with JSON storage and APIs.

Features:
---------
- UUID-based unique product ID generation
- Object representation of products with name, price, quantity, and description
- Easy conversion to and from dictionaries for JSON I/O

Usage:
-------
product = Product("Laptop", 999.99, 10)
product_dict = product.to_dict()
product_obj = Product.from_dict(product_dict)
"""


import uuid


class Product:
    """
    Represents a product in the e-commerce system.
    """
    def __init__(self, name: str, price: float, quantity: int,
                 description: str = "", product_id: str = None):
        """
        Initializes a new Product instance.

        Args:
            name (str): Name of the product
            price (float): Product price
            quantity (int): Stock quantity
            description (str, optional): Product description. Defaults to "".
            product_id (str, optional): Existing ID for loading from storage. If not provided, a new UUID is generated.
        """
        self.product_id = product_id or str(uuid.uuid4())
        self.name = name
        self.price = price
        self.quantity = quantity
        self.description = description

    def to_dict(self):
        """
        Converts the product instance to a dictionary.

        Returns:
            dict: Dictionary representation of the product
        """
        return {
            "product_id": self.product_id,
            "name": self.name,
            "price": self.price,
            "quantity": self.quantity,
            "description": self.description
        }

    @staticmethod
    def from_dict(data):
        """
        Creates a Product instance from a dictionary.

        Args:
            data (dict): Dictionary containing product fields

        Returns:
            Product: A Product instance initialized from the dictionary
        """
        return Product(
            name=data["name"],
            price=data["price"],
            quantity=data["quantity"],
            description=data.get("description", ""),
            product_id=data["product_id"]
        )
