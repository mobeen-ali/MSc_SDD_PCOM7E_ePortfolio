import bcrypt


class User:
    def __init__(self, username, plain_password):
        self.username = username
        self._password_hash = self._hash_password(plain_password)

    def _hash_password(self, password):
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode('utf-8'), salt)

    def check_password(self, input_password):
        return bcrypt.checkpw(input_password.encode('utf-8'), self._password_hash)


class AdminUser(User):
    def __init__(self, username, password, access_level):
        super().__init__(username, password)
        self.access_level = access_level

    def promote_user(self, target_user):
        print(f"User {target_user.username} has been promoted by {self.username}.")


def main():
    # Create a regular user
    user1 = User("mobeen", "SecurePass123")
    # Create an admin user
    admin = AdminUser("admin_mobeen", "AdminPass456", access_level=5)

    # Simulate login attempt
    input_pw = "SecurePass123"
    if user1.check_password(input_pw):
        print(f"[SUCCESS] Login successful for user: {user1.username}")
    else:
        print(f"[FAIL] Login failed for user: {user1.username}")

    # Simulate admin action
    admin.promote_user(user1)


if __name__ == "__main__":
    main()
