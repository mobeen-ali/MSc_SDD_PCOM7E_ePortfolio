# ✅ Unit 7 Summary – Secure Shells, REST APIs & Ontological Modelling

## 🧠 Learning Outcomes Mastered

This unit delivered a technically rigorous application of secure software development principles through discrete, hands-on activities. It covered:

- Ontological modelling to define and formalize relationships between secure system components  
- Development of a hardened Python Command Line Interface (CLI) shell with restricted commands and validated input handling  
- Implementation and validation of a REST (Representational State Transfer) API using the Flask microframework  
- Analysis of architectural shifts from monolithic systems to serverless computing, based on contemporary academic sources  

Each task was designed and executed independently, enabling practical mastery of security mechanisms, software architecture, and structured data interaction.

---

## 📁 Deliverables & Technical Artefacts

### 🔹 [`unit7_activity_secure_shell.py`](./Activity_Exploring_a_Simple_Python_Shell/unit7_activity_secure_shell.py)
Custom-built secure CLI shell supporting four commands (`LIST`, `ADD`, `HELP`, `EXIT`). Input handling was sanitised to prevent injection and misuse. Exit logic was tightly controlled to prevent infinite loop execution.

### 🔹 [`unit7_activity_simple_python_shell.md`](./Activity_Exploring_a_Simple_Python_Shell/unit7_activity_simple_python_shell.md)
Security analysis document identifying two critical vulnerabilities:
- Denial of Service (DoS) risk via uncontrolled input loops  
- Absence of audit logging (violating OWASP A10:2021 – Insufficient Logging and Monitoring)

Each issue was addressed with corrective strategies and pseudocode illustrations.

### 🔹 [`distributed_environment_api.py`](./Activity_API_for_Distributed_Environment/distributed_environment_api.py)
Flask-based RESTful API with full CRUD (Create, Read, Update, Delete) functionality for user records. Implements:
- HTTP methods: `GET`, `POST`, `PUT`, `DELETE`  
- Validation through `reqparse`  
- Status responses: `200 OK`, `201 Created`, `400 Bad Request`, `404 Not Found`

#### 📸 Evidence:
- [`run-result_distributed_environment_api.png`](./Activity_API_for_Distributed_Environment/screenshots/run-result_distributed_environment_api.png): Flask server execution  
- [`api_get_user_Ann.png`](./Activity_API_for_Distributed_Environment/screenshots/api_get_user_Ann.png): Successful GET request  
- [`api_get_user_Adam.png`](./Activity_API_for_Distributed_Environment/screenshots/api_get_user_Adam.png): GET request with 404 error  

### 🔹 [`api_questions_answers.md`](./Activity_API_for_Distributed_Environment/api_questions_answers.md)
Provides detailed answers to REST interaction tasks, including correct usage of cURL and HTTP method semantics, with secure design commentary.

### 🔹 [`ontology_and_architecture.md`](./ontology_and_architecture.md)
Defines a domain-specific ontology for secure CLI systems. Models entities such as `User`, `Command`, `Authentication`, and `LogEntry`.  
The file also presents a concise architectural analysis of software evolution from monoliths to microservices to Function-as-a-Service (FaaS), grounded in Salah et al. (2016).

---

## 🧪 Security Testing Summary

**Test Script:** [`test_secure_os_access.py`](./test_secure_os_access.py)  
**Scope:**
- Verified secure creation and access control of temporary files using `tempfile`  
- Confirmed correct use of `subprocess.run()` with `shell=False` to mitigate command injection risks

**Result:** All test cases executed successfully on Windows 11.  
`os.chmod` was invoked but has no effect on Windows file permissions, this limitation was noted and documented, with no impact on core functionality or security in the Windows environment.

---

## 📚 Academic References

GDPR (n.d.) General Data Protection Regulation (EU). Available at: https://gdpr-info.eu/ (Accessed: 4 June 2025).

OWASP Foundation (2021) OWASP Top Ten: The Ten Most Critical Web Application Security Risks. Available at: https://owasp.org/Top10 (Accessed: 4 June 2025).

Saltzer, J.H. and Schroeder, M.D. (1975) ‘The protection of information in computer systems’, Proceedings of the IEEE, 63(9), pp. 1278–1308. https://doi.org/10.1109/PROC.1975.9939

Salah, T., Jamal, T., Pranggono, B., Karam, R., Hussain, R. and Jayaraman, R. (2016) ‘The evolution of distributed systems towards microservices architecture’, International Journal of Advanced Computer Science and Applications (IJACSA), 7(10), pp. 141–147. https://doi.org/10.14569/IJACSA.2016.071018

