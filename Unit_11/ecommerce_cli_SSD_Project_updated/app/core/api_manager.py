"""
Filename: api_manager.py
Author: Mobeen Ali
Date: July 2025

Purpose:
--------
Handles outbound HTTP requests to the external Fake Store API.
Used to simulate real-world integration by pushing product data to a demo API.

Security & Performance Notes:
-----------------------------
- Timeout is enforced to prevent hanging.
- Only validated product data is sent.
- Logs are recorded for all outcomes to support monitoring and auditing.
- Fixed API key and category are used only for demo/testing purposes.

Reference:
----------
Fake Store API Docs: https://fakestoreapi.com/
"""


import requests
from app.core.logger import Logger

API_URL = "https://fakestoreapi.com/products"
API_KEY = "demo-api-key-123"  # Not actually used in headers (for illustration only)


class APIManager:
    """
    A utility class to manage external API interactions.
    """
    @staticmethod
    def push_product(product_data: dict) -> bool:
        """
        Sends product data to the external Fake Store API.

        Args:
            product_data (dict): Dictionary containing at least 'name', 'price', and 'quantity'.

        Returns:
            bool: True if the push was successful, False otherwise.
        """
        try:
            # Prepare headers and payload
            headers = {
                "Content-Type": "application/json"
            }
            # Basic validation of required fields
            if not all(k in product_data for k in ["name", "price", "quantity"]):
                Logger.warning("Invalid product data passed to API")
                return False

            payload = {
                "title": product_data["name"],
                "price": product_data["price"],
                "description": product_data.get("description", ""),
                "category": "electronics"  # fixed for demo
            }
            # Send POST request to Fake Store API
            response = requests.post(API_URL, json=payload, headers=headers, timeout=5)

            # Handle response
            if response.status_code in [200, 201]:
                Logger.info(f"Pushed to Fake Store API: {product_data['name']}")
                return True
            else:
                Logger.warning(f"API error: {response.status_code} - {response.text}")
                return False
        except Exception as e:
            Logger.error(f"API request failed: {str(e)}")
            return False
