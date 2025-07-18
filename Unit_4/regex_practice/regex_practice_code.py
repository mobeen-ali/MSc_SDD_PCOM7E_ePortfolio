import re


def is_valid_email(email):
    """
    Validates an email using a safe regex pattern.
    """
    # Safe and common regex for email validation
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w{2,}$'
    return re.match(pattern, email) is not None


def vulnerable_regex_test(input_string):
    """
    Demonstrates a regex vulnerable to ReDoS via catastrophic backtracking.
    """
    # Vulnerable regex pattern (too greedy)
    pattern = r'(a+)+$'

    try:
        match = re.match(pattern, input_string)
        return bool(match)
    except Exception as e:
        return f"Regex failed: {e}"


if __name__ == "__main__":
    # Safe test
    email = "example@email.com"
    print(f"Valid email? {email}: {is_valid_email(email)}")

    # ReDoS demo (this will hang with long strings like 'a'*10_000 + '!')
    test_input = 'a' * 100 + '!'
    print(f"Vulnerable regex test on input length {len(test_input)}: {vulnerable_regex_test(test_input)}")

