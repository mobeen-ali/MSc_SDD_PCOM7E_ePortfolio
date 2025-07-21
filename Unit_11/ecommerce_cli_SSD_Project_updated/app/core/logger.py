"""
Filename: logger.py
Author: Mobeen Ali
Date: July 2025

Purpose:
--------
Provides centralized logging functionality for the Secure CLI E-Commerce Application.
Supports INFO, WARNING, and ERROR level logs written to a rotating log file.

Key Features:
-------------
- Ensures logs are stored in a dedicated /logs directory
- Records timestamped logs for key system events
- Helps monitor login attempts, registration, API actions, and security toggles

Log Format:
-----------
[YYYY-MM-DD HH:MM:SS] | LEVEL | Message

Example:
---------
2025-07-14 10:15:20 | INFO | User 'alice' registered successfully
"""

import logging
import os

# Log file configuration
LOG_FILE = "activity.log"

# Ensure logs directory exists
os.makedirs("logs", exist_ok=True)

# Configure logging format and destination
logging.basicConfig(
    filename=os.path.join("logs", LOG_FILE),
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)


class Logger:
    """
    Static Logger class for writing application logs.
    """
    @staticmethod
    def info(message: str):
        """
        Log an informational message.

        Args:
            message (str): The message to log
        """
        logging.info(message)

    @staticmethod
    def warning(message: str):
        """
        Log a warning message.

        Args:
            message (str): The message to log
        """
        logging.warning(message)

    @staticmethod
    def error(message: str):
        """
        Log an error message.

        Args:
            message (str): The message to log
        """
        logging.error(message)
