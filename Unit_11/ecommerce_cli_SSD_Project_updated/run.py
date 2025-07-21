"""
Filename: run.py
Author: Mobeen Ali
Date: July 2025

Purpose:
--------
This is the entry point for the Secure CLI E-Commerce Application.

It initializes the Click-based CLI defined in `app/cli.py`, enabling
users to register, authenticate, and manage products securely via terminal commands.

Usage:
-------
$ python run.py [COMMANDS]

For available commands, run:
$ python run.py --help

Security Note:
--------------
Click is used to handle command-line parsing securely.
All interactions are routed through validated and structured commands,
reducing the risk of injection or malformed input attacks.

See README.md for detailed usage instructions.
"""

from app.cli import cli # Importing CLI group from the app package

if __name__ == "__main__":
    # Entry point for the application – starts the CLI
    cli()
