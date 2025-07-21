"""
secure_os_demo.py

A security-focused demonstration of:
1. Temporary file handling with strict access controls
2. Subprocess usage that avoids command injection

"""

import os
import tempfile
import subprocess


def list_temp_files():
    """
    Securely creates and reads a temporary file.

    Key Security Practices:
    - File is created with auto-deletion enabled (`delete=True`)
    - Uses restrictive permissions (rw-------) to enforce access control
    - Prevents leakage of sensitive data to other users
    """

    print("[*] Creating secure temporary file...")

    with tempfile.NamedTemporaryFile(
        delete=True, mode='w+', prefix='secure_', suffix='.txt'
    ) as temp_file:
        print(f"[INFO] Temporary file created: {temp_file.name}")
        
        # Write sensitive data
        temp_file.write("Sensitive data goes here.\n")
        temp_file.flush()  # Ensure content is written to disk

        # Restrict permissions: owner read/write only (chmod 600)
        os.chmod(temp_file.name, 0o600)

        print("[INFO] File permissions set to 600 (rw-------)")

        # Securely read the contents back
        print("\n[READ] File content:")
        with open(temp_file.name, 'r') as file:
            print(file.read().strip())  # Remove trailing newline


def run_secure_ls():
    """
    Runs a secure version of the `ls -la` command using subprocess.

    Security Considerations:
    - `shell=False` to avoid shell injection
    - Uses explicit list of arguments
    - Captures and prints standard output and error securely
    """
    print("\n[*] Executing secure 'ls -la' command...")

    try:
        result = subprocess.run(
            ["ls", "-la"],
            capture_output=True,
            text=True,
            check=True
        )
        print("[SUCCESS] Command Output:\n")
        print(result.stdout)

    except subprocess.CalledProcessError as err:
        print(f"[ERROR] Subprocess failed with message:\n{err.stderr}")


def main():
    """
    Entry point for secure OS access demo
    """
    print("========================================")
    print(" Secure OS Access Demo – CLI Simulation ")
    print("========================================\n")

    list_temp_files()
    run_secure_ls()

    print("========================================\n")
    print("\n[*] Secure OS access demo completed.")
    print("========================================\n")


if __name__ == "__main__":
    main()
