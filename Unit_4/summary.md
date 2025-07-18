# Unit 4 Summary – Regular Expressions, Recursion, and System Security

## 🧠 Key Learning

This unit explored how **regular expressions (regex)** and **recursion** offer powerful programming techniques but can introduce critical vulnerabilities if not carefully implemented.

From a security perspective:
- Poorly written regex can result in **ReDoS (Regular Expression Denial of Service)** due to excessive backtracking.
- Improper use of recursion can lead to **stack overflow**, denial of service, or unexpected program crashes.

The key learning was that even built-in language features can become **attack surfaces** if not treated with a secure design mindset.

---

## 🛠 Artefacts

### 🔹 `regex_practice/regex_practice_code.py`
A script that:
- Validates email addresses using a safe regex pattern
- Demonstrates a vulnerable pattern that can trigger backtracking (e.g., `(a+)+$`)

### 🔹 `recursion_practice/recursion_practice_code.py`
A script that:
- Recursively lists files in a directory
- Includes `max_depth` logic to prevent stack overflow and excessive traversal

---

## 🧪 Testing & Results

Test scripts were written for both artefacts to ensure expected behavior and resilience.

### ✅ `regex_practice/test_regex_practice.py`
- Tests valid and invalid email patterns
- Handles vulnerable input safely without crash

📷 ![Regex Tests Passed](./regex_practice/run-result_test_regex_practice_code.png)

### ✅ `recursion_practice/test_recursion_practice.py`
- Builds nested directories using `tmp_path`
- Ensures recursive listing does not exceed max depth

📷 ![Recursion Tests Passed](./recursion_practice/run-result_test_recursion_practice_code.png)

---

## 📚 References

OWASP Foundation (2021) *Regular Expression Denial of Service (ReDoS)*. Available at: https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service (Accessed: 17 July 2025).

Romano, F. and Krüger, H. (2021) *Learn Python Programming: The Definitive Guide to Writing Clean Python Code*. 4th edn. Birmingham: Packt Publishing.

Olmsted, A. (2020) *Security-Driven Software Development: Defending the Digital Frontier*. Boca Raton: CRC Press.
