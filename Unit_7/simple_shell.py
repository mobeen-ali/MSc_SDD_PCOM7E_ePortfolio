import os
import sys


def list_directory():
    """
    Lists the contents of the current directory.
    Uses built-in `os.listdir()` to avoid OS command injection risks.
    """
    print("\n[DIR LISTING]")
    for item in os.listdir():
        print(f" - {item}")
    print()


def add_numbers():
    """
    Prompts user for two numbers and adds them.
    Includes input validation to prevent runtime errors.
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
    print("""
Available Commands:
  LIST   - List contents of the current directory
  ADD    - Add two numbers
  HELP   - Show this help message
  EXIT   - Exit the shell
""")


def shell_loop():
    """
    Main loop for the command shell.
    """
    print("Secure Python Shell. Type HELP for available commands.\n")

    while True:
        command = input(">>> ").strip().upper()

        if command == "LIST":
            list_directory()
        elif command == "ADD":
            add_numbers()
        elif command == "HELP":
            show_help()
        elif command == "EXIT":
            print("Exiting shell...")
            sys.exit(0)
        else:
            print("Unknown command. Type HELP for available options.\n")


if __name__ == "__main__":
    try:
        shell_loop()
    except KeyboardInterrupt:
        print("\n[Shell exited via Ctrl+C]")
