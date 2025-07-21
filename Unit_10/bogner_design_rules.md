# Relevance of Bogner et al. (2023) Design Rules to the CLI Application

Bogner et al. (2023) outline a comprehensive set of design rules aimed at producing secure, modular, and maintainable software systems. The secure Command Line Interface (CLI) e-commerce application adheres to these principles in the following ways:

- **Encapsulation and Separation of Concerns**: Authentication, encryption, and logging functionalities are implemented as discrete modules (`authenticator.py`, `data_manager.py`, etc.), ensuring a clear separation of responsibilities and reducing interdependencies.

- **Secure Defaults**: Security features are enabled by default. Passwords are hashed using `bcrypt` and Two-Factor Authentication (2FA) is enforced via One-Time Passwords (OTPs) using the PyOTP library. These mechanisms reduce the risk of unauthorized access.

- **Principle of Least Privilege**: Role-Based Access Control (RBAC) is applied to distinguish between regular users and administrative users. However, the system currently lacks fine-grained permission controls.

- **Low Coupling**: The CLI input logic is strictly separated from business logic, preserving modularity and simplifying future maintenance or feature expansion.

- **Use of Trusted Libraries**: All third-party dependencies (PyOTP, bcrypt, Fernet, Click) are widely used, actively maintained, and aligned with the Open Worldwide Application Security Project (OWASP) recommendations.

- **Establishment of Trust Chains**: Multi-session management was not implemented during development, as the application was scoped exclusively for local execution. The absence of distributed authentication flows was an intentional simplification aligned with the system's standalone, single-user context.

- **Comprehensive Logging**: All user and administrative actions, including those from the simulated attacker module, are timestamped and recorded for auditability and incident tracing.

These implementations collectively contribute to the system’s maintainability, auditability, and resistance to common security threats, despite the constrained context of solo local development.
