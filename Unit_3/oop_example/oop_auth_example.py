import bcrypt


class User:
    """
    A class representing a user with secure password management
    using bcrypt hashing.

    Attributes:
        username (str): The user's identifier.
        _password_hash (bytes): Secure hash of the user's password.
    """

    def __init__(self, username, plain_password):
        """
        Initializes a User instance with a hashed password.

        Args:
            username (str): The username of the user.
            plain_password (str): The plaintext password to be securely hashed.
        """
        self.username = username
        self._password_hash = self._hash_password(plain_password)

    def _hash_password(self, password):
        """
        Hashes the provided plaintext password using bcrypt.

        Args:
            password (str): The plaintext password to hash.

        Returns:
            bytes: The hashed password.
        """
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode('utf-8'), salt)

    def check_password(self, input_password):
        """
        Verifies if the provided input password matches the stored
        hashed password.

        Args:
            input_password (str): The plaintext password input by the user.

        Returns:
            bool: True if passwords match, False otherwise.
        """
        return bcrypt.checkpw(input_password.encode('utf-8'),
                              self._password_hash)


class AdminUser(User):
    """
    A subclass of User with administrative privileges.

    Attributes:
        access_level (int): Level of administrative access granted to the user.
    """

    def __init__(self, username, password, access_level):
        """
        Initializes an AdminUser with specified administrative access.

        Args:
            username (str): Admin username.
            password (str): Admin password.
            access_level (int): Admin's access level.
        """
        super().__init__(username, password)
        self.access_level = access_level

    def promote_user(self, target_user):
        """
        Simulates the action of promoting another user.

        Args:
            target_user (User): The user being promoted.
        """
        print(f"[ADMIN ACTION] User '{target_user.username}' has been promoted"
              f"by Admin '{self.username}'.")


def main():
    """
    Main function demonstrating user creation, authentication,
    and admin actions.
    """
    print("\n=== Secure User Authentication & Admin Simulation ===\n")

    # Step 1: Create a regular user
    user1 = User("mobeen", "SecurePass123")
    print(f"[INFO] User '{user1.username}' has been successfully created.")

    # Step 2: Create an admin user
    admin = AdminUser("admin_mobeen", "AdminPass456", access_level=5)
    print(f"[INFO] Admin user '{admin.username}' created"
          f"with access level '{admin.access_level}'.")

    # Step 3: Simulate a user login attempt
    print("\n--- Simulating User Login ---")
    # Password provided by user during login attempt
    input_pw = "SecurePass123"

    if user1.check_password(input_pw):
        print(f"[SUCCESS] Login successful for user: '{user1.username}'")
    else:
        print(f"[FAIL] Login failed for user: '{user1.username}'")

    # Step 4: Simulate an administrative action
    print("\n--- Admin Performing User Promotion ---")
    admin.promote_user(user1)

    print("\n=== End of Simulation ===\n")


if __name__ == "__main__":
    main()
