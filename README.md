# 🔐 MSc Secure Software Development – E-Portfolio

**Student:** Mobeen Ali  
**Module Code:** PCOM7E  
**Course:** MSc Computer Science (University of Essex Online)  
**Assessment:** Secure Software Development E-Portfolio Submission

---

## 📘 Overview

This e-Portfolio presents the secure software engineering work completed during the MSc module. It includes theory, code, tests, diagrams, logs, and reflections. The final outcome is a fully tested, secure Command-Line Interface (CLI) e-commerce system with authentication, encryption, logging, and role-based access control.

**⚠️ Important Note:** This portfolio contains two versions of the Unit 11 project:
- **Original Version** (`Unit_11/ecommerce_cli_SSD_Project/`): Initial submission that received 41% grade
- **Revised Version** (`Unit_11/ecommerce_cli_SSD_Project_updated/`): **REVISED VERSION** demonstrating growth and feedback integration

The revised version shows work completed to address feedback and demonstrate learning, but is not an official resubmission.

---

## 📝 How to Review This Portfolio

This portfolio is organized for clarity and ease of navigation. Please use the following guidance to review the submission:

1. **Start with the README.md** for an overview of the portfolio structure and key documents.
2. **Refer to `NAVIGATION.md`** for a unit-by-unit artefact map and quick links to all major files.
3. **Consult `ARTEFACTS_INDEX.md`** for a detailed list of all artefacts, including code, diagrams, tests, documents, and videos, organized by unit.
4. **The revised Unit 11 implementation (`Unit_11/ecommerce_cli_SSD_Project_updated/`) is the artefact submitted for Assessment 3.** The original version (`Unit_11/ecommerce_cli_SSD_Project/`) is included for context only, to demonstrate learning progression.
5. **Testing evidence, demonstration videos, and evaluation documents** are referenced in the artefact index and navigation guide.
6. **Reflection and evaluation documents** are located in the `Unit_12/` folder.
7. **Use the `SUBMISSION_CHECKLIST.md`** to verify that all assignment requirements are fulfilled.

If you have any questions about the structure or contents, please refer to the navigation aids or contact the student using the details provided in this README.

---

## 📁 Complete Portfolio Structure

```
SSD_E-Portfolio/
├── Unit_1/                          # Threat modeling and OWASP flowcharts
│   ├── DIagram_Source_FIles/        # Draw.io source files
│   ├── Flowchart_A05-2021_Security_Misconfiguration.png
│   ├── Sequence_Diagram_A05-2021_Security_Misconfiguration.png
│   └── unit-01_summary.md
├── Unit_2/                          # Secure SDLC and Agile UML reflections
│   └── unit-02_summary.md
├── Unit_3/                          # OOP and secure language practices
│   ├── oop_example/                 # OOP authentication example
│   │   ├── oop_auth_example.py
│   │   ├── test_oop_auth.py
│   │   ├── test_run_screenshot.png
│   │   └── TESTING_and_RUNNING_oop_auth_example_script.mp4
│   ├── secure_language_discussion.md
│   └── unit-03_summary.md
├── Unit_4/                          # Regex security and recursion
│   ├── recursion_practice/          # Recursion implementation
│   │   ├── recursion_practice_code.py
│   │   ├── test_recursion_practice_code.py
│   │   ├── run-result_test_recursion_practice_code.png
│   │   └── TESTING_and_RUNNING_recursion_practice_code_script.mp4
│   ├── regex_practice/              # Regex security practices
│   │   ├── regex_practice_code.py
│   │   ├── test_regex_practice_code.py
│   │   ├── run-result_test_regex_practice_code.png
│   │   └── TESTING_and_RUNNING_regex_practice_code_script.mp4
│   ├── regex_security_summary.md
│   └── unit-04_summary.md
├── Unit_5/                          # Equivalence partitioning
│   ├── modulo_3_relation.png
│   ├── modulo_4_relation.png
│   ├── unit05_activity_equivalence_partitioning_demo.ipynb
│   └── unit-05_summary.md
├── Unit_6/                          # Design document and static analysis
│   ├── flake8_demonstration_evidence/
│   │   └── fixing_oop_auth_example_script_with_flake8.mp4
│   ├── flake8_screenshots/
│   │   ├── flake8_oop_auth_example_analysis.png
│   │   ├── flake8_regex_practice_code_analysis.png
│   │   └── flake8_recursion_practice_code_analysis.png
│   ├── team_meetings/               # Collaborative work evidence
│   │   ├── 30May2025_meeting-minutes.txt
│   │   ├── 04June2025_meeting-minutes.txt
│   │   ├── 05June2025_meeting-minutes.txt
│   │   └── 08June2025_meeting-minutes.txt
│   ├── Peer Evaluation - Design Document.docx
│   ├── Secure_Software_Development_Group_Project_Design_Document.docx
│   └── unit-06_summary.md
├── Unit_7/                          # Distributed API and secure shell
│   ├── Activity_API_for_Distributed_Environment/
│   │   ├── distributed_environment_api.py
│   │   ├── api_questions_answers.md
│   │   ├── RUNNING_EVIDENCE_for_API-for-a-Distributed-Environment.mp4
│   │   └── screenshots/
│   ├── Activity_Exploring_a_Simple_Python_Shell/
│   │   ├── unit7_activity_secure_shell.py
│   │   ├── input_flood_simulation.py
│   │   ├── unit7_activity_simple_python_shell.md
│   │   ├── secure_shell.log
│   │   └── UNIT-7_Simple-Shell_ACTIVITY_DEMONSTRATION_EVIDENCE.mp4
│   ├── ontology_and_architecture.md
│   ├── secure_os_access.py
│   ├── test_secure_os_access.py
│   └── unit-07_summary.md
├── Unit_8/                          # File encryption in Python
│   ├── encryption_practice/
│   │   ├── file_encryptor.py
│   │   ├── encryption_explanation.md
│   │   ├── encrypted_output.txt
│   │   └── input.txt
│   └── unit-08_summary.md
├── Unit_9/                          # API refactoring with validation
│   ├── distributed_environment_api_v2.py
│   ├── test_distributed_environment_api_v2.py
│   ├── RUNNING_EVIDENCE_for_Distributed_Environment_API_Updated_Code.mp4
│   └── unit-09_summary.md
├── Unit_10/                         # Faceted data and secure design rules
│   ├── bogner_design_rules.md
│   ├── faceted_data_reflection.md
│   └── unit-10_summary.md
├── Unit_11/                         # 🚀 FINAL PROJECT: Secure CLI e-commerce
│   ├── ecommerce_cli_SSD_Project/           # Original version (41% grade)
│   ├── ecommerce_cli_SSD_Project_updated/   # ⭐ REVISED VERSION (Additional work)
│   │   ├── app/                            # Main application code
│   │   ├── tests/                          # Comprehensive test suite
│   │   ├── FINAL_PROJECT_EVALUATION.md     # Comprehensive evaluation
│   │   ├── TESTING_EVIDENCE.md             # Complete testing documentation
│   │   ├── DEMO_COMMANDS.md                # Demonstration commands
│   │   ├── PROJECT_STRUCTURE.md            # Detailed architecture
│   │   ├── DEMONSTRATION_RECORDING.mp4     # Video demonstration
│   │   └── README.md                       # Setup and usage instructions
│   ├── PROJECT_EVOLUTION_SUMMARY.md         # Growth demonstration
│   └── unit-11_summary.md
├── Unit_12/                         # Final reflection and evaluation
│   ├── Reflection_on_the_Secure_Software_Development_Module_v1.1.docx
│   ├── Unit11_Implementation_Evaluation.md   # Implementation vs. design analysis
│   └── unit-12_summary.md
├── NAVIGATION.md                    # 📋 Complete navigation guide
├── folder_structure.txt             # 📁 Detailed folder structure
├── generate_structure.py            # 🔧 Structure generation script
└── README.md                       # 📖 This file
```

---

## 🗂️ Folder Structure

| Folder            | Description                                                                 |
|-------------------|-----------------------------------------------------------------------------|
| `Unit_1`–`Unit_5` | Diagrams, summaries, and security-focused Python exercises                  |
| `Unit_6`          | Group design document with OWASP (Open Worldwide Application Security Project) threat mapping |
| `Unit_7`–`Unit_10`| Cryptography, REST (Representational State Transfer) API (Application Programming Interface), testing, data access control |
| `Unit_11`         | **FINAL PROJECT**: Secure CLI e-commerce project with full source code, tests, logs |
| `Unit_12`         | Final module reflection using Rolfe et al. (2001) reflective model          |

---

## 🛠️ Key Technologies Used

- **Python 3.11**
- `Click` – CLI framework for user input handling
- `bcrypt`, `Fernet`, `PyOTP` – for password hashing, encryption, and two-factor authentication (2FA)
- `Flask`, `Flask-RESTful` – for REST API implementation
- `pytest`, `flake8`, `pylint` – for unit testing, code linting, and compliance with PEP8 (Python Enhancement Proposal 8)

---

## ✅ Learning Outcomes Demonstrated

- Secure system architecture and modular code
- OWASP Top 10 threat mitigation applied to real implementations
- GDPR (General Data Protection Regulation)-compliant data handling and pseudonymisation
- Role-based access control with audit logging
- Full test coverage via unit tests and manual functional testing
- Use of version control and Kanban for solo development workflow

---

## 🚀 Running the Final Project

**REVISED VERSION**: Go to: `Unit_11/ecommerce_cli_SSD_Project_updated/`
1. Open `README.md` inside for setup and execution instructions
2. Review `app/core/` for comprehensive security implementations
3. Check `FINAL_PROJECT_EVALUATION.md` for detailed implementation vs. design analysis

**ORIGINAL VERSION** (for comparison): `Unit_11/ecommerce_cli_SSD_Project/`

---

## 📋 Key Documents for Reviewers

### **Primary Documents**
- [`NAVIGATION.md`](NAVIGATION.md) – Complete navigation guide with all artefacts
- [`Unit_11/PROJECT_EVOLUTION_SUMMARY.md`](Unit_11/PROJECT_EVOLUTION_SUMMARY.md) – Growth demonstration
- [`Unit_11/ecommerce_cli_SSD_Project_updated/FINAL_PROJECT_EVALUATION.md`](Unit_11/ecommerce_cli_SSD_Project_updated/FINAL_PROJECT_EVALUATION.md) – Comprehensive evaluation
- [`Unit_12/Unit11_Implementation_Evaluation.md`](Unit_12/Unit11_Implementation_Evaluation.md) – Implementation vs. design analysis
- [`ARTEFACTS_INDEX.md`](ARTEFACTS_INDEX.md) – Complete index of all artefacts by unit
- [`SUBMISSION_CHECKLIST.md`](SUBMISSION_CHECKLIST.md) – Final checklist to verify all requirements are met

### **Final Project Files**
- [`Unit_11/ecommerce_cli_SSD_Project_updated/`](Unit_11/ecommerce_cli_SSD_Project_updated/) – **REVISED VERSION** (This is the artefact submitted for Assessment 3, reflecting my improved understanding and secure development skills.)
- [`Unit_11/ecommerce_cli_SSD_Project/`](Unit_11/ecommerce_cli_SSD_Project/) – **ORIGINAL VERSION** (Included for context only, to demonstrate learning progression.)
- [`Unit_12/Reflection_on_the_Secure_Software_Development_Module_v1.1.docx`](Unit_12/Reflection_on_the_Secure_Software_Development_Module_v1.1.docx) – Module reflection

### **Supporting Evidence**
- [`Unit_6/team_meetings/`](Unit_6/team_meetings/) – Collaborative work evidence
- [`Unit_11/ecommerce_cli_SSD_Project_updated/TESTING_EVIDENCE.md`](Unit_11/ecommerce_cli_SSD_Project_updated/TESTING_EVIDENCE.md) – Complete testing documentation
- [`folder_structure.txt`](folder_structure.txt) – Detailed portfolio structure

---

## 🔎 Integrity and Authorship

All code, documentation, and diagrams are original unless explicitly cited. Libraries used are acknowledged in source files or markdown documents. All development was completed for academic purposes and adheres to university standards of academic integrity.

---

## 📫 Contact

**GitHub:** [github.com/mobeen-ali](https://github.com/mobeen-ali)  
**Email:** mobeenali.t@gmail.com
