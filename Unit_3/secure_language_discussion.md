
# 🧠 Unit 3 Activity – What is a Secure Programming Language?

### 🔍 What factors determine whether a programming language is secure or not?

- **Memory safety**: The language should prevent buffer overflows, dangling pointers, and memory leaks.
- **Type safety**: Strong, static typing can help catch bugs early and prevent unintended behaviour.
- **Error handling**: Built-in mechanisms to handle exceptions and faults securely.
- **Sandboxing and permissions**: Ability to restrict code execution and access to resources.
- **Standard library safety**: Built-in functions should avoid introducing common vulnerabilities.
- **Tooling support**: Availability of linters, static analyzers, and security-focused packages.

### 🐍 Could Python be classed as a secure language?

Yes, **Python** can be considered secure for most application-level programming, especially when best practices are followed.

**Reasons:**
- It enforces memory safety by abstracting low-level memory access.
- Exceptions help handle errors predictably.
- The large community maintains strong libraries with security in mind.
- Python encourages readable and maintainable code, reducing logic errors.

However, Python is not suitable for scenarios requiring direct hardware control or performance-critical secure systems (e.g., OS-level kernels).

### 💻 Python vs C for Operating System Development

Python is **not suitable** for creating full-fledged operating systems compared to C.

**Reasons:**
- Python is interpreted, not compiled, which limits performance and control.
- C provides low-level access to memory and hardware essential for OS development.
- Python relies on an interpreter that itself is often written in C or C++.

However, Python is superior for rapid development, prototyping, scripting, and higher-level secure software, especially in web, automation, and data processing domains.
