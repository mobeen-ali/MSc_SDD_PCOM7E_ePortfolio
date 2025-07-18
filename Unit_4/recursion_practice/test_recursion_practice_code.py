import os
import pytest
from recursion_practice_code import recursive_list_files


def test_recursion_does_not_crash(tmp_path):
    # Setup: create nested folders
    current = tmp_path
    for i in range(6):
        current = current / f"level_{i}"
        current.mkdir()

    # Should not raise an error due to max_depth=5
    try:
        recursive_list_files(str(tmp_path))
    except RecursionError:
        pytest.fail("RecursionError occurred when it shouldn't")
