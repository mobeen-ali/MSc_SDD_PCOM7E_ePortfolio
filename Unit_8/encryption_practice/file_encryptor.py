from cryptography.fernet import Fernet

# Generate and save the key
key = Fernet.generate_key()
with open("encryption_key.key", "wb") as key_file:
    key_file.write(key)

# Load the key
with open("encryption_key.key", "rb") as key_file:
    key = key_file.read()

fernet = Fernet(key)

# Read the plaintext from input file
with open("input.txt", "rb") as file:
    original_data = file.read()

# Encrypt the data
encrypted_data = fernet.encrypt(original_data)

# Write encrypted data to a new file
with open("encrypted_output.txt", "wb") as file:
    file.write(encrypted_data)

print("Encryption complete. Output written to 'encrypted_output.txt'.")