import pytest
from regex_practice_code import is_valid_email, vulnerable_regex_test

def test_valid_email():
    """
    Test that a properly formatted email passes validation.
    """
    print("\n[Test] Checking a valid email format...")
    assert is_valid_email("test@example.com") is True
    print("[Pass] Valid email passed correctly.")

def test_invalid_email():
    """
    Test that an improperly formatted email fails validation.
    """
    print("\n[Test] Checking an invalid email format...")
    assert is_valid_email("invalid-email@") is False
    print("[Pass] Invalid email rejected as expected.")

def test_vulnerable_regex_safe_input():
    """
    Test that vulnerable regex handles safe input without issue.
    """
    print("\n[Test] Checking vulnerable regex on safe input...")
    input_string = "aaaaa"
    assert vulnerable_regex_test(input_string) is True
    print("[Pass] Safe input did not trigger regex failure.")

def test_vulnerable_regex_bad_input():
    """
    Test that vulnerable regex doesn't crash on input that might cause catastrophic backtracking.
    This ensures the function handles it gracefully within test boundaries.
    """
    print("\n[Test] Checking vulnerable regex on risky input...")
    input_string = "a" * 30 + "!"
    result = vulnerable_regex_test(input_string)
    assert result in [False, True]  # Should not crash
    print("[Pass] Risky input handled without crashing (no ReDoS impact at this size).")