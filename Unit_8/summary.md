# ✅ Unit 8 Summary – Cryptography and Secure Data Storage

## 🧠 Key Learning

This unit focused on practical applications of **cryptographic algorithms** in Python to secure textual data. I explored the `cryptography` module's Fernet encryption method and applied it to encrypt the contents of a file. Additionally, I reflected on the algorithm’s alignment with **GDPR** compliance requirements.

This reinforced key security principles like **confidentiality, integrity, and secure key management**.

---

## 📁 Artefacts

### 🔹 Python Encryption Script – `file_encryptor.py`
- Reads a file (`input.txt`)
- Encrypts its contents using `Fernet` symmetric encryption
- Saves encrypted output to `encrypted_output.txt`
- Key is stored in a separate file `encryption_key.key`

### 🔹 Explanation Markdown – `encryption_explanation.md`
Covers:
- Why Fernet was chosen (AES + HMAC, ease of use)
- GDPR alignment (data protection, key control, breach mitigation)

### 🔹 Screenshot (Not Included Yet)
Showcasing the successful encryption output and files created.

---

## 🔐 Security & Compliance Considerations

- Ensures that plaintext data is never stored or transmitted unencrypted
- Key storage must be handled separately from encrypted data
- Demonstrates “data protection by design” (GDPR Article 25)

---

## 📚 Reference

TutorialsPoint (no date) *Cryptography with Python*. Available at: https://www.tutorialspoint.com/cryptography_with_python/index.htm (Accessed: 17 July 2025)