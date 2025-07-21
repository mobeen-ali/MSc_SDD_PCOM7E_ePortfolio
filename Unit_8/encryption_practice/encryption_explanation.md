# Unit 8 – Cryptography Programming Exercise

## Algorithm Selection

The encryption algorithm selected for this task is **Fernet symmetric encryption**, implemented using the `cryptography` package in Python. Fernet is a high-level, authenticated cryptographic system that provides:

- **Confidentiality**: Employs Advanced Encryption Standard (AES) in Cipher Block Chaining (CBC) mode.
- **Integrity**: Utilises Hash-based Message Authentication Code (HMAC) with SHA-256 to prevent tampering.
- **Simplicity**: Abstracts key management, encoding, and decoding within a secure application programming interface (API).
- **Security**: Enforces cryptographic best practices such as random key generation, time-stamped tokens, and automatic key rotation.

These characteristics make Fernet highly suitable for command-line interface (CLI) and desktop-based file encryption tasks requiring secure, reversible data protection with minimal configuration.

---

## General Data Protection Regulation (GDPR) Compliance Evaluation

The implementation of Fernet encryption addresses multiple obligations set out in the General Data Protection Regulation (GDPR) (European Union Regulation 2016/679).

### Data Protection by Design and Default (Article 25)
- Encryption is implemented as a non-optional behaviour in the script, ensuring personal data is protected by default.
- Both data at rest (`encrypted_output.txt`) and any transmission processes (e.g. moving files) are encrypted.

### Reversibility with Controlled Access
- Decryption is only possible using a securely stored symmetric key (`encryption_key.key`), thus satisfying the **accountability** and **confidentiality** principles.

### Breach Impact Minimisation (Article 32)
- Exposure of encrypted data does not compromise the content unless the decryption key is also exposed.
- This mitigates the risk of data leakage in the event of unauthorised access.

### Implementation Caveats
- **Key management practices must be secure**: Keys must not be stored in the same location or repository as encrypted data.
- **Operational security measures** (e.g. logging, authentication, access control) should accompany encryption in production systems.

---

## Encryption Script I/O Overview

- **Input file**: `input.txt` – Original plaintext content.
- **Output file**: `encrypted_output.txt` – Encrypted binary content.
- **Key file**: `encryption_key.key` – Contains base64-encoded symmetric key (Fernet-compliant).

---

## Reference

TutorialsPoint (no date) *Cryptography with Python*. Available at: https://www.tutorialspoint.com/cryptography_with_python/index.htm (Accessed: 17 July 2025).

GDPR (no date) *General Data Protection Regulation (EU)*. Available at: https://gdpr-info.eu/ (Accessed: 17 July 2025).
