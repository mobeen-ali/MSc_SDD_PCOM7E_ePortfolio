# 🧠 Ontology and Architecture Evolution

## 📘 Understanding Ontology in Software Systems

Ontology in software systems refers to a structured representation of **concepts, relationships, and categories** within a specific domain. It defines a shared vocabulary for developers and systems to interpret data consistently, support automation, and enable interoperability.

According to the Unit 7 readings (Saltzer and Schroeder, 1975; Al-Boghdady et al., 2021), an ontology helps in understanding and mapping **assets, threats, vulnerabilities, and countermeasures** in a secure system.

---

## 📌 Ontology for My Secure CLI System

Below is a simplified ontology designed for the secure CLI system developed throughout this module:

**Entities:**
- `User`
- `Authentication` (e.g., Password, 2FA)
- `Command`
- `DataStorage`
- `LogEntry`

**Relationships:**
- `User` performs `Command`
- `Command` creates `LogEntry`
- `Authentication` grants access
- `Command` accesses `DataStorage`
- `LogEntry` associated with `User`

This ontology helps trace user behavior, enforce least privilege, and map vulnerabilities to mitigation techniques.

---

## 🏛️ Architecture Evolution (Extending Salah et al., 2016)

### From Microservices to Cloud-Native and Serverless

**Post-Microservices Trends:**
- **Cloud-Native Applications** use containers, orchestration (Kubernetes), and DevSecOps for agile delivery and built-in security.
- **Serverless Architectures** (e.g., AWS Lambda, Azure Functions) eliminate infrastructure concerns and scale automatically.
- **API-first Design** is a core enabler, making systems modular and testable.
- **Zero Trust Security Models** are now being enforced within distributed services.

### Key Considerations:
- Stateless functions simplify patching and monitoring
- Observability (logs, traces, metrics) is prioritized from day one
- Identity-aware access control replaces network perimeter defenses

These changes reflect a shift from managing systems to managing **security-driven services**.

---

## 📚 References

Al-Boghdady, A., Wassif, K. and El-Ramly, M. (2021) ‘The Presence, Trends, and Causes of Security Vulnerabilities in Operating Systems of IoT’s Low-End Devices’, *Sensors*, 21(7), p. 2329.

Saltzer, J.H. and Schroeder, M.D. (1975) ‘The Protection of Information in Computer Systems’, *Proceedings of the IEEE*, 63(9), pp. 1278–1308.

Salah, K., et al. (2016) ‘Architectural evolution in cloud computing: microservices vs. monoliths’, *International Journal of Advanced Computer Science and Applications*, 7(10), pp. 141–147.