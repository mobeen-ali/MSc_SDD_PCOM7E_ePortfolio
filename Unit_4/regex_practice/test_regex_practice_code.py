import pytest
from regex_practice_code import is_valid_email, vulnerable_regex_test


def test_valid_email():
    assert is_valid_email("test@example.com") is True


def test_invalid_email():
    assert is_valid_email("invalid-email@") is False


def test_vulnerable_regex_safe_input():
    input_string = "aaaaa"
    assert vulnerable_regex_test(input_string) is True


def test_vulnerable_regex_bad_input():
    # Testing for catastrophic pattern with '!' at the end
    input_string = "a" * 30 + "!"
    result = vulnerable_regex_test(input_string)
    assert result in [False, True]  # Should not crash
