# Unit 10 – Faceted Data Control, Systematic Testing, and Architectural Rigor

## Literature-Driven System Fortification

Two primary academic sources were scrutinised and operationalised:

- **Schmitz et al. (2016)** proposed the *faceted data model*, a fine-grained data access control mechanism. In response, a minimal Python prototype was constructed to demonstrate **Role-Based Access Control (RBAC)** in practice—assigning user-facing visibility strictly based on role-level clearance, thereby reducing data leakage vectors.

- **Bogner et al. (2023)** articulated seven pragmatic principles for **Microservice-Oriented Architecture (MOA)**. The application conforms to at least three: **modularity** (discrete, reusable components), **secure-by-default configuration** (e.g. encryption, access control toggles), and **clear separation of logic layers** (e.g. Command Line Interface (CLI) interaction vs. authentication engine).

## Test Validation Protocols

Testing was not introduced in Unit 10 but rather integrated from Units 7 and 8 onward. Core validation was executed using `pytest` across critical modules: user registration, authentication, product lifecycle (Create, Read, Update, Delete), and admin-only commands.

Security assurance testing simulated brute-force and One-Time Password (OTP) replay attacks via a custom `hacker.py` script, verifying the integrity of **Two-Factor Authentication (2FA)** mechanisms and login attempt restrictions.

Code compliance with **PEP8** (Python Enhancement Proposal 8) was assured using `flake8`. No logical or syntactical violations were recorded.

## Stored Deliverables

- [`faceted_data_reflection.md`](./faceted_data_reflection.md): Explains the use of role-based filters for secure output rendering.
- [`bogner_design_rules.md`](./bogner_design_rules.md): Condensed critique and alignment with MOA design principles.
