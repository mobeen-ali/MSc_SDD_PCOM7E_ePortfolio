# Unit 11 – Implementation vs. Design Proposal Evaluation  
**Secure CLI E-Commerce Application**

## Preface

This evaluation is based on a revised implementation of the secure CLI e-commerce application. The original submission for Unit 11 did not fully meet the specification, resulting in a failing grade. Following feedback and reflection on the Unit 6 Design Document and assessment criteria, the system was re-engineered to address the shortcomings and go beyond the original scope.

This document evaluates the **final version of the implementation** against the **original design proposal**, highlighting how the updated implementation fulfils and exceeds the original functional, security, and quality expectations.

---

## 1. Introduction

This evaluation compares the final implementation of the secure Python CLI e-commerce application with the group design proposal submitted in Unit 6. The assessment follows key criteria from the design: functionality, security (via OWASP Top 10), architecture, testing strategy, and academic compliance. It also highlights any deviations and justifies implementation decisions using academic and practical rationale.

---

## 2. Functional Implementation Assessment

### ✅ E-Commerce Features

| Feature | Design Intent | Final Status | Notes |
|--------|----------------|--------------|-------|
| User Registration & Login | Password authentication (bcrypt) with 2FA (PyOTP) | ✔️ Fully implemented | Role-based access enabled |
| Product Management | CRUD operations on products | ✔️ Fully implemented | Includes admin-only commands |
| Shopping Cart & Orders | Session-like cart and order processing | ✔️ Fully implemented | Persistence achieved using JSON |
| Payment & Shipping | Simulated payment options and shipping info | ✔️ Fully implemented | Payment is simulated as per design assumption |

📝 **Comment**: All specified features were implemented. Enhancements include session persistence and OTP-based security, exceeding the original functional scope.

---

## 3. Security Feature Compliance (OWASP Top 10)

| OWASP Category | Design Plan | Implementation Summary | Status |
|----------------|-------------|-------------------------|--------|
| A01 – Broken Access Control | Role-based admin access | Admin-only toggle for security settings | ✅ |
| A02 – Cryptographic Failures | bcrypt password hashing | Encrypted JSON + Fernet module | ✅ |
| A03 – Injection | Input validation and Click CLI | Validated commands and sanitisation | ✅ |
| A04 – Insecure Design | Modular threat-aware structure | Added simulated hacker module | ✅ |
| A05 – Security Misconfiguration | Safe defaults, role enforcement | Config lockdown, safe error messages | ✅ |
| A06 – Vulnerable Components | Use of safe libraries | Dependency audit using `pip-audit` | ✅ |
| A07 – Authentication Failures | Password policy, 2FA | Rate-limited login, OTP protection | ✅ |
| A08 – Software Integrity | Integrity checks via hashes | Simulated integrity tracking | ✅ |
| A09 – Logging & Monitoring | Account event logging | Custom logger, log rotation, anomaly flags | ✅ |
| A10 – SSRF | N/A in CLI context | Not applicable | ✅ (Not applicable) |

📝 **Comment**: Implementation not only covers all designed OWASP categories but introduces deeper controls (e.g., SIEM-style logging, hacker simulation) appropriate for CLI environments.

---

## 4. Architecture & Modularity

The final application preserves and enhances the modular object-oriented structure outlined in the UML diagram:

```
app/
├── core/                 # Business and security logic
│   ├── auth.py           # Auth and 2FA
│   ├── crypto_manager.py # Encryption and hashing
│   ├── logger.py         # Logging and monitoring
│   └── ...               # Other security modules
├── models/              # User and Product classes
├── cli.py               # Main Click-based CLI
```

- Implements clear separation of concerns.
- Each module supports isolated unit testing.
- Supports scalable future extension (e.g., adding CLI roles).

---

## 5. Testing, Validation & Quality Assurance

| Area | Tool/Approach | Result |
|------|---------------|--------|
| Unit Testing | `pytest` | ✅ Full coverage for all modules |
| Static Analysis | `flake8` | ✅ PEP8 compliance verified |
| Security Testing | Simulated attacks + Bandit | ✅ Password, OTP, replay, injection |
| Functional Testing | Manual CLI path tests | ✅ Passed all user/admin flows |
| Documentation | Markdown and README.md | ✅ Includes setup, usage, test evidence |

📝 **Comment**: The test suite not only meets but exceeds expectations, demonstrating high-quality and maintainable secure software development.

---

## 6. Deviations from Original Design

| Aspect | Design Intent | Final Implementation | Justification |
|--------|----------------|----------------------|---------------|
| Storage | JSON-based with encryption | File-based encrypted persistence | Chosen for simplicity, focus on security principles |
| Web Interface | Not required | CLI only | CLI ensures focus on security without web complexities |
| Payment Integration | Simulated or real | Simulated | Avoided external services for privacy and simplicity |
| CLI Design | Standard CLI | Context-aware CLI | Enhances UX, especially with role-based command access |
| Admin Tools | Basic role control | Admin panel with logging, session toggle, key management | Provides production-like realism |

---

## 7. Limitations and Future Work

| Limitation | Future Improvement |
|------------|--------------------|
| No GUI/Web | Web interface could be developed using Flask |
| File Storage | Switch to encrypted database (e.g., SQLite with SQLCipher) |
| Static CLI Role | Introduce dynamic user permissions |
| GDPR Deletion | Implement CLI command for personal data removal |
| Exception Handling | Expand to include structured error tracing and fallback |

---

## 8. Standards and Academic References

The implementation aligns with:

- **OWASP Top 10 (2021)**: Full coverage with CLI-relevant adaptations.
- **NIST Cybersecurity Framework**: Identification, protection, detection, response, and recovery principles.
- **ISO/IEC 27001:2013**: Emphasis on secure design, auditing, access control, and encryption.
- **Secure SDLC (NIST SP 800-64)**: Structured development phases with testing and risk mitigation.
- **Key Sources**:
  - OWASP Foundation (2021)
  - Olmsted (2020)
  - Romano & Krüger (2021)
  - McGraw (2006), Viega & McGraw (2002)
  - GDPR (EU, 2018)
  - PEP8 (van Rossum et al., 2001)

---

## 9. Conclusion

The final secure CLI application **meets and exceeds** the original Unit 6 design proposal:

- ✅ Implements all required e-commerce and security features
- ✅ Exceeds OWASP-based requirements through layered defences
- ✅ Delivers clean, modular architecture aligned with good design practices
- ✅ Demonstrates high test coverage and security validation
- ✅ Adheres to academic expectations in software engineering and cybersecurity

This implementation not only reflects a robust grasp of secure development principles, but also translates theory into a working, defensible system suitable for educational and future production contexts.

---

## 10. References

- OWASP Foundation. (2021). *OWASP Top 10: The Ten Most Critical Web Application Security Risks*. Retrieved from https://owasp.org/Top10/
- National Institute of Standards and Technology. (2018). *Framework for Improving Critical Infrastructure Cybersecurity*. Retrieved from https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.04162018.pdf
- International Organization for Standardization. (2013). *ISO/IEC 27001:2013 Information technology — Security techniques — Information security management systems — Requirements*. Retrieved from https://www.iso.org/standard/54534.html
- National Institute of Standards and Technology. (2008). *NIST Special Publication 800-64 Revision 2: Security Considerations in the System Development Life Cycle*. Retrieved from https://csrc.nist.gov/publications/detail/sp/800-64/rev-2/final
- Olmsted, A. (2020). *Security-Driven Software Development: Defending the Digital Frontier*. Jones & Bartlett Learning.
- Romano, F., & Krüger, H. (2021). *Learn Python Programming: A Beginner’s Guide to Coding*. Packt Publishing.
- McGraw, G. (2006). *Software Security: Building Security In*. Addison-Wesley Professional.
- Viega, J., & McGraw, G. (2002). *Building Secure Software: How to Avoid Security Problems the Right Way*. Addison-Wesley Professional.
- van Rossum, G., Warsaw, B., & Coghlan, N. (2001). *PEP 8 – Style Guide for Python Code*. Python Software Foundation. Retrieved from https://peps.python.org/pep-0008/
