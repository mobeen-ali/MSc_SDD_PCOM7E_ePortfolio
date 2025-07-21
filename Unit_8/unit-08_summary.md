# Unit 8 Summary – Cryptography and Secure Data Storage

## Key Learning

This unit examined the applied use of cryptographic algorithms in Python for secure data handling. The primary focus was on **symmetric encryption** using the **Fernet** method from the `cryptography` package. A script was developed to read plaintext from a file, encrypt it using a symmetric key, and output the ciphertext to a new file. The symmetric key was securely stored in a separate file.

This activity concretised the following principles:

- **Confidentiality**: Data is unreadable without the correct decryption key.
- **Integrity**: Fernet incorporates HMAC (Hash-based Message Authentication Code), preventing tampering.
- **Key Management**: Secure separation of encryption keys from data files was enforced.
- **Compliance**: The design aligns with **General Data Protection Regulation (GDPR)** (European Union Regulation 2016/679) requirements for “data protection by design”.

## Artefacts

### Python Script: [`file_encryptor.py`](./encryption_practice/file_encryptor.py)
- Inputs: [`input.txt`](./encryption_practice/input.txt)
- Method: Encrypts contents using Fernet (AES128 + HMAC)
- Outputs: [`encrypted_output.txt`](./encryption_practice/encrypted_output.txt)
- Key Management: Stores key in [`encryption_key.key`](./encryption_practice/encryption_key.key)

### Technical Explanation: [`encryption_explanation.md`](./encryption_practice/encryption_explanation.md)
This document provides a precise rationale for algorithm selection and its security implications:
- Justification for using Fernet (AES in CBC mode with PKCS7 padding, authenticated via HMAC)
- Explicit mapping of implementation to GDPR Articles 5 and 25
- Discussion of limitations and secure deployment considerations

### Screenshot (Pending Inclusion)
Demonstrates successful encryption execution and generation of artefacts.

## Security and Compliance Considerations

- No plaintext is persisted or transmitted at any stage of execution.
- Encryption key is stored independently of data to reduce breach impact.
- The implementation supports **data minimisation** and **user privacy by architecture**, directly fulfilling GDPR mandates under Articles 25 (Data Protection by Design and Default) and 32 (Security of Processing).
- The use of established cryptographic primitives ensures resistance to common attack vectors such as brute-force, known-plaintext, and chosen-ciphertext attacks.

## Reference

TutorialsPoint (no date) *Cryptography with Python*. Available at: https://www.tutorialspoint.com/cryptography_with_python/index.htm (Accessed: 17 July 2025).

GDPR (no date) *General Data Protection Regulation (EU)*. Available at: https://gdpr-info.eu/ (Accessed: 17 July 2025).
