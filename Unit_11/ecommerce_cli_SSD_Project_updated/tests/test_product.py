"""
Filename: test_product.py
Author: Mobeen Ali
Date: July 2025

Purpose:
--------
Unit tests for product management in the Secure CLI E-Commerce Application.

Tests cover:
- Adding a product
- Updating product attributes
- Deleting a product

Storage:
---------
All tests are isolated using a temporary test_products.json file.
"""


import os
import pytest
from app.core import auth, storage
from app.models.product import Product

# Isolated test file path
TEST_PRODUCTS_DB = "test_products.json"

@pytest.fixture(autouse=True)
def isolate_products(monkeypatch):
    """
    Pytest fixture to redirect product DB to a test file.
    Cleans up test file before and after each test.
    """
    monkeypatch.setattr(auth, "PRODUCTS_DB", TEST_PRODUCTS_DB)
    if os.path.exists(TEST_PRODUCTS_DB):
        os.remove(TEST_PRODUCTS_DB)
    yield
    if os.path.exists(TEST_PRODUCTS_DB):
        os.remove(TEST_PRODUCTS_DB)

def test_add_product_and_list():
    """
    Test creating and saving a new product, then reading it back.
    Verifies:
    - Product is stored by ID
    - Fields are accurately saved
    """
    product = Product(name="SSD Drive", price=99.99, quantity=5, description="1TB NVMe SSD")
    products = {}
    products[product.product_id] = product.to_dict()
    auth._save_products(products)

    loaded = auth._load_products()
    assert product.product_id in loaded
    assert loaded[product.product_id]["name"] == "SSD Drive"


def test_update_product():
    """
    Test updating an existing product's price and quantity.
    Ensures that:
    - Changes persist after save/load
    """
    product = Product(name="Mouse", price=25.5, quantity=10)
    products = {product.product_id: product.to_dict()}
    auth._save_products(products)

    # Update values
    loaded = auth._load_products()
    loaded[product.product_id]["price"] = 29.99
    loaded[product.product_id]["quantity"] = 8
    auth._save_products(loaded)

    updated = auth._load_products()
    assert updated[product.product_id]["price"] == 29.99
    assert updated[product.product_id]["quantity"] == 8


def test_delete_product():
    """
    Test deleting a product from storage.
    Verifies the product is removed completely.
    """
    product = Product(name="Keyboard", price=70.0, quantity=3)
    products = {product.product_id: product.to_dict()}
    auth._save_products(products)

    # Delete and verify
    loaded = auth._load_products()
    del loaded[product.product_id]
    auth._save_products(loaded)

    result = auth._load_products()
    assert product.product_id not in result

