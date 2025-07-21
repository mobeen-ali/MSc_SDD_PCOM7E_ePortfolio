"""
input_flood_simulation.py – Demonstrates lack of throttling in unit7_activity_secure_shell.py

This script floods unit7_activity_secure_shell.py with rapid HELP commands to showcase
input abuse and potential Denial-of-Service (DoS) vulnerability.

Author: Mobeen Ali
"""

import subprocess
import time

def run_flood():
    """
    Launches unit7_activity_secure_shell.py and floods it with commands.
    Compatible with Windows and other platforms.
    """
    print("[INFO] Starting input flood on unit7_activity_secure_shell.py...")

    try:
        # Open shell without capturing stdout/stderr (Windows-safe)
        process = subprocess.Popen(
            ["python", "unit7_activity_secure_shell.py"],
            stdin=subprocess.PIPE,
            text=True
        )

        for i in range(500):  # 500 inputs to simulate load
            process.stdin.write("HELP\n")
            process.stdin.flush()
            time.sleep(0.005)  # Tweak to simulate realistic rapid input

        print("[INFO] Flood completed. Terminating shell...")
        time.sleep(1)
        process.terminate()

    except Exception as e:
        print(f"[ERROR] Flooding failed: {e}")

if __name__ == "__main__":
    run_flood()
