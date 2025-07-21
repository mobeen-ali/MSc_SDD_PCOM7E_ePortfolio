# Unit 6 Summary – Linters and Secure Python Design

## Core Insight

Security begins with clarity. Linters enforce that clarity. This unit operationalized tools like `flake8` and `bandit` to enforce **PEP8 compliance** and uncover insecure code patterns—*before* they reach production. Secure coding is not opinion—it’s process. And linters formalize that process.

## Design Document & Feedback

### Group Design Document  
**Filename:** [`Secure_Software_Development_Group_Project_Design_Document.docx`](../Unit_6/Secure_Software_Development_Group_Project_Design_Document.docx)  
A formally structured blueprint. It defined:

- Modular CLI architecture using Python
- Risk mapping based on **OWASP Top 10 (2021)**: A03, A05, A07, A10
- 2FA with `PyOTP`, password hashing with `bcrypt`, encrypted data storage
- Diagrams: Class and Misuse Activity
- Tools: `Click`, `pytest`, `Keyring`
- Development methodology: solo Git-based pipelines, TDD, Kanban

### Tutor Feedback  
**Filename:** [`Peer Evaluation - Design Document.docx`](../Unit_6/Peer%20Evaluation%20-%20Design%20Document.docx)  
Dr. Cathryn Peoples assessed the design as **Merit (69%)** overall. She praised:

- Diagrammatic clarity
- Team synergy
- OWASP-grounded thinking

Critiques included:
- Inconsistent mention of 2FA and password policy
- Limited specificity on monitoring/logging and input validation
- Over-reliance on a single source (D’Adamo et al., 2021)

---

## Linter Demonstration

Linting was applied to sample scripts used earlier in Units 3 and 4 (not part of the core Unit 6 code). `flake8` identified style violations such as line length, unused imports, and inconsistent indentation. All issues were fixed, and final analysis showed **zero PEP8 violations**.

| Script                             | Linter Status   |
|------------------------------------|-----------------|
| `oop_auth_example.py`             | ✅ Clean        |
| `regex_practice_code.py`          | ✅ Clean        |
| `recursion_practice_code.py`      | ✅ Clean        |

Screenshots:  
- `flake8_screenshots/flake8_oop_auth_example_analysis.png`  
- `flake8_screenshots/flake8_regex_practice_code_analysis.png`  
- `flake8_screenshots/flake8_recursion_practice_code_analysis.png`  

Demonstration Recording:  
- `flake8_demonstration_evidence/oop_auth_example_flake8_fixing.mp4`

---

## Team Coordination

Team collaboration was time-boxed, role-specific, and milestone-driven. Meetings were structured and documented:

| Date         | File                                                   | Agenda Highlights                                                                 |
|--------------|--------------------------------------------------------|--------------------------------------------------------------------------------------|
| 30-May-2025  | `team_meetings/30May2025_meeting-minutes.txt`         | Document structure, section allocation, word count breakdown, diagram collaboration |
| 04-Jun-2025  | `team_meetings/04June2025_meeting-minutes.txt`        | Misuse diagram finalization, system implementation, user/order handling logic       |
| 05-Jun-2025  | `team_meetings/05June2025_meeting-minutes.txt`        | Document polishing, timeline addition, Mermaid tools, login limit policy edits      |
| 08-Jun-2025  | `team_meetings/08June2025_meeting-minutes.txt`        | Final edits, OWASP reorder, word count trim, Turnitin submission, LinkedIn sharing  |

Recordings: [Microsoft OneDrive Recordings Folder](https://1drv.ms/f/c/2465e7dfd9d61c67/Es5_eFzPN6RLvoBI1SIhXIoB4bfXI6hBdtQmlvY6dBawmg?e=l49K4N)

---

## Application

This unit laid the security scaffolding for Unit 11:
- **Secure coding is provable. Linters prove it.**
- **Design without implementation is theory. This was practice.**
- **Feedback wasn’t ignored—it was actioned.**

Every line of code linted, every role clarified, every threat modeled—this was the bridge between intention and execution.

---

## References

- Romano, F. and Krüger, H. (2021). *Learn Python Programming*. 4th edn. Packt.
- Olmsted, A. (2020). *Security-Driven Software Development*. CRC Press.
- Python Software Foundation (2001). *PEP 8 – Style Guide for Python Code*. [https://peps.python.org/pep-0008/](https://peps.python.org/pep-0008/)
- OWASP Foundation (2021). *OWASP Top Ten Security Risks*. [https://owasp.org/Top10](https://owasp.org/Top10)
