import os
import tempfile
import subprocess


def list_temp_files():
    """
    Securely create and list temporary files.
    Uses restricted file permissions and auto-delete mode.
    """
    with tempfile.NamedTemporaryFile(delete=True, mode='w+', prefix='secure_', suffix='.txt') as temp_file:
        print(f"Temporary file created at: {temp_file.name}")
        temp_file.write("Sensitive data goes here.\n")
        temp_file.flush()

        # Change file permissions to rw------- (only owner can read/write)
        os.chmod(temp_file.name, 0o600)

        print("\n[INFO] Listing contents securely:")
        with open(temp_file.name, 'r') as file:
            print(file.read())


def run_secure_ls():
    """
    Demonstrates secure subprocess usage to list directory contents.
    Avoids shell=True to prevent command injection.
    """
    print("\n[INFO] Running 'ls' command using subprocess (no shell)...")
    try:
        result = subprocess.run(["ls", "-la"], capture_output=True, text=True, check=True)
        print(result.stdout)
    except subprocess.CalledProcessError as err:
        print(f"[ERROR] Subprocess failed: {err}")


if __name__ == "__main__":
    print("[*] Starting secure OS access demo...\n")
    list_temp_files()
    run_secure_ls()
    print("\n[*] Secure OS access demo completed.")
