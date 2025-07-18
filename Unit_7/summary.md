# ✅ Unit 7 Summary – Secure Shells, REST APIs & Ontologies

## 🧠 Key Learning

This unit focused on secure system design from both theoretical and practical standpoints. Key topics included:
- Understanding ontologies and their use in modeling secure systems
- Designing and analyzing custom Python CLI shells for command handling
- Creating and testing RESTful APIs using Flask
- Mapping software architecture evolution beyond microservices

I applied these concepts to build a secure CLI shell, RESTful API, and wrote test cases to evaluate code behavior. I also created an ontology model for my CLI system and extended ideas from Salah et al. (2016) to modern cloud architectures.

---

## 📁 Artefacts

### 🔹 Custom Shell – `simple_shell.py`
Implements four commands (`LIST`, `ADD`, `HELP`, `EXIT`) and includes input handling.

### 🔹 Security Analysis – `shell_security_notes.md`
Outlined two key vulnerabilities (infinite input loop and no audit logging) and proposed fixes with pseudocode.

### 🔹 Flask REST API – `distributed_environment_api.py`
Implements CRUD operations on a sample user list. Includes GET, POST, PUT, DELETE methods using Flask-RESTful.

**Screenshots:**
- `api_run_output.png` – API running in terminal
- `api_get_user_ann.png` – GET request returning 200 OK
- `api_get_user_adam.png` – GET request returning 404 Not Found

### 🔹 API Interaction Answers – `api_questions_answers.md`
Includes answers and reasoning for all required API execution questions.

### 🔹 Ontology & Architecture – `ontology_and_architecture.md`
Defines a simplified ontology relevant to the secure CLI app and presents trends from microservices to serverless systems.

---

## 🧪 Testing

A custom script (`test_secure_os_access.py`) was created to verify secure use of `tempfile` permissions and subprocess behavior. Results were partially passed, highlighting OS differences.

---

## 🤝 Collaboration

Although this unit focused more on individual implementation, it followed the team-led design submitted in Unit 6. Seminar feedback and documentation were used to guide the development.

---

## 📚 References

- Saltzer, J.H. and Schroeder, M.D. (1975) ‘The Protection of Information in Computer Systems’, *IEEE*, 63(9), pp. 1278–1308.
- Salah, T., et al. (2016) ‘The evolution of distributed systems towards microservices architecture’, *IJACSA*, 7(10), pp. 141–147.
- Al-Boghdady, A., Wassif, K. and El-Ramly, M. (2021) ‘The Presence...’, *Sensors*, 21(7), p. 2329.