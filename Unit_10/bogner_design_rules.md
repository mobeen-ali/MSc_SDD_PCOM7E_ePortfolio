# 🏗️ Relevance of Bogner et al. (2023) Design Rules to My System

Bogner et al.'s design principles for secure, modular systems were largely reflected in my CLI application.

- ✅ **Encapsulation & Separation**: Authentication, encryption, and logging were modularized (`authenticator.py`, `data_manager.py`, etc.), following clear separation of concerns.
- ✅ **Secure Defaults**: Security mode is enabled by default; bcrypt and 2FA are enforced.
- ⚠️ **Least Privilege**: Basic role-based access (user vs admin) implemented; no fine-grained permissions.
- ✅ **Low Coupling**: CLI logic and business logic remain decoupled.
- ✅ **Trusted Libraries**: Used PyOTP, bcrypt, Fernet, and Click, following OWASP-recommended practices.
- ⚠️ **Trust Chains**: No multi-session control, but acceptable for a local CLI use case.
- ✅ **Logging**: All actions logged with timestamps; hacker actions also recorded.

These alignments helped ensure a maintainable, auditable, and secure CLI system, even within the constraints of a solo local project.