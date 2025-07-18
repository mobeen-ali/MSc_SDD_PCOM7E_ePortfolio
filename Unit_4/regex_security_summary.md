
# 🔐 Unit 4 – Programming Language Concepts: Regular Expressions & Security

### ❓ What is Evil Regex?

**Evil Regex** refers to regular expressions crafted (intentionally or unintentionally) in a way that causes **catastrophic backtracking**, leading to high CPU usage and performance degradation. This can be exploited in **ReDoS (Regular Expression Denial of Service)** attacks.

### ⚠️ Common Problems with Regex

- **Catastrophic backtracking** in complex or greedy patterns
- **Unreadable expressions** leading to maintenance issues
- **Overly permissive matches** or unintended edge cases

**Mitigation Strategies:**
- Use regex validators/testers to detect vulnerable patterns
- Set execution timeouts for regex operations where supported
- Prefer simpler and more specific patterns
- Use libraries or engines designed to avoid backtracking issues (e.g., RE2)

### 🔐 Regex as a Security Tool

Regex can be effectively used to:
- **Sanitise inputs** and prevent injection attacks (e.g., SQLi, XSS)
- **Validate formats** like email, phone, or ID numbers securely
- **Detect patterns** in logs or traffic for intrusion detection

However, regex must be carefully designed to avoid introducing its own vulnerabilities.

