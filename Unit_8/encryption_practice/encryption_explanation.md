# 🔐 Unit 8 – Cryptography Programming Exercise

## 🔍 Algorithm Selection

I chose **Fernet symmetric encryption** from the `cryptography` Python package. Fernet is a high-level and easy-to-use algorithm that provides:
- **Confidentiality**: It uses AES in CBC mode with a SHA256 HMAC for integrity.
- **Simplicity**: Built-in key management, encoding, and decoding.
- **Security**: Random key generation and strong cryptographic primitives.

This makes it an ideal choice for file-based encryption in CLI or desktop applications.

---

## 📜 GDPR Compliance Evaluation

Fernet encryption **supports GDPR compliance** in the following ways:

### ✅ Data Protection by Design
- Encryption is implemented as a default behavior.
- Data is protected both at rest and in transit.

### ✅ Reversibility with Access Control
- Only individuals with access to the key file (`encryption_key.key`) can decrypt the data, fulfilling GDPR’s accountability principle.

### ✅ Breach Minimization
- If data is exposed without the key, it remains unreadable, reducing the impact of potential breaches.

### ⚠️ Considerations
- Key management must be secure and compliant (e.g., keys not stored alongside data).
- Should be paired with authentication and audit mechanisms in production environments.

---

## 📄 Notes

- Input file: `input.txt`
- Output file: `encrypted_output.txt`
- Key file: `encryption_key.key`

---

## 📚 Reference

TutorialsPoint (no date) *Cryptography with Python*. Available at: https://www.tutorialspoint.com/cryptography_with_python/index.htm (Accessed: 17 July 2025)