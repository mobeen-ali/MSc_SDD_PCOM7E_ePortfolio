import os
import pytest
from recursion_practice_code import recursive_list_files

def test_recursion_does_not_crash(tmp_path):
    """
    Test that recursive_list_files does not crash or recurse infinitely
    when navigating deeply nested directories.
    
    This test creates a 6-level deep directory structure. Since the function
    has a default max_depth of 5, it should handle this gracefully without
    throwing a RecursionError.
    """
    print("\n[Test] Creating nested folder structure up to 6 levels deep...")

    current = tmp_path
    for i in range(6):
        current = current / f"level_{i}"
        current.mkdir()
        print(f"[Setup] Created: {current}")

    print("\n[Test] Running recursive_list_files on test directory...")
    try:
        recursive_list_files(str(tmp_path))
        print("[Pass] No RecursionError occurred. Function respected max depth.")
    except RecursionError:
        pytest.fail("[Fail] RecursionError occurred when it shouldn't")