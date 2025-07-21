"""
secure_shell.py – A secure and minimal Python command-line shell

Implements basic shell functionality:
- LIST: List current directory contents
- ADD: Perform addition of two numbers
- HELP: Show supported commands
- EXIT: Exit the shell

Security-conscious design with:
- Input validation
- Logging
- Defensive programming
- PEP8 compliance

Author: Mobeen Ali
"""

import os
import logging

# Setup audit logging
logging.basicConfig(filename='secure_shell.log',
                    level=logging.INFO,
                    format='%(asctime)s - %(message)s')


def list_directory():
    """
    Lists the contents of the current directory.
    Uses os.listdir() to avoid command injection risks.
    """
    print("\n[DIR LISTING]")
    try:
        for item in os.listdir():
            print(f" - {item}")
    except Exception as e:
        print(f"[ERROR] Unable to list directory contents: {e}")
    print()


def add_numbers():
    """
    Prompts user for two numbers and returns their sum.
    Handles non-numeric input gracefully.
    """
    try:
        a = float(input("Enter first number: "))
        b = float(input("Enter second number: "))
        print(f"Result: {a} + {b} = {a + b}\n")
    except ValueError:
        print("[ERROR] Invalid input. Please enter numeric values only.\n")


def show_help():
    """
    Displays available commands in the shell.
    """
    print("""\nAvailable Commands:
  LIST   - List contents of the current directory
  ADD    - Add two numbers
  HELP   - Show this help message
  EXIT   - Exit the shell
""")


def shell_loop():
    """
    Main loop for the secure shell.
    Logs all commands and handles unknown entries.
    """
    print("Secure Python Shell. Type HELP for available commands.\n")

    while True:
        try:
            command = input(">>> ").strip().upper()
            logging.info(f"Command entered: {command}")

            if command == "LIST":
                list_directory()
            elif command == "ADD":
                add_numbers()
            elif command == "HELP":
                show_help()
            elif command == "EXIT":
                print("Exiting shell...")
                break
            else:
                print("[ERROR] Unknown command."
                      "Type HELP for available options.\n")

        except KeyboardInterrupt:
            print("\n[INFO] Shell exited via Ctrl+C")
            break
        except Exception as e:
            print(f"[ERROR] Unexpected error: {e}")
            logging.error(f"Unhandled exception: {e}")


if __name__ == "__main__":
    shell_loop()
