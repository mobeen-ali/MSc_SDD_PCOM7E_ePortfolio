import re

def is_valid_email(email):
    """
    Validates an email address using a safe and widely accepted regex pattern.

    Args:
        email (str): Email address to validate.

    Returns:
        bool: True if email is valid, False otherwise.
    """
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w{2,}$'
    return re.match(pattern, email) is not None

def vulnerable_regex_test(input_string):
    """
    Demonstrates a regex pattern vulnerable to Regular Expression Denial of Service (ReDoS)
    due to catastrophic backtracking when handling long repetitive patterns.

    Args:
        input_string (str): The string to test against the vulnerable regex.

    Returns:
        bool or str: Match result or error message.
    """
    pattern = r'(a+)+$'  # Vulnerable: nested quantifiers over the same character class

    try:
        match = re.match(pattern, input_string)
        return bool(match)
    except Exception as e:
        return f"Regex failed: {e}"

if __name__ == "__main__":
    print("\n==========================================")
    print("      Regex Validation & ReDoS Demo       ")
    print("==========================================\n")

    # Safe email validation
    email = "example@email.com"
    print(f"[INFO] Checking if '{email}' is a valid email...")
    print(f"[RESULT] Valid email? {is_valid_email(email)}\n")

    # Vulnerable regex demonstration
    test_input = 'a' * 30 + '!'
    print(f"[INFO] Testing vulnerable regex with input of length {len(test_input)}...")
    print(f"[RESULT] Vulnerable regex match result: {vulnerable_regex_test(test_input)}")

    print("\n[NOTE] For true ReDoS effect, use much longer input (e.g., 'a'*10_000+'!') ... not recommended in demonstration.")
    print("\n==========================================")
    print("               End of Demo               ")
    print("==========================================\n")
