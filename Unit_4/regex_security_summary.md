# Unit 4 – Programming Language Concepts: Regular Expressions & Security

---

## Evil Regex Defined

**Evil Regular Expression (Regex)** denotes a pattern engineered—intentionally or negligently—to invoke **catastrophic backtracking**, resulting in exponential processing time. This pathological behavior enables **Regular Expression Denial of Service (ReDoS)**, a vector for targeted system disruption via high Central Processing Unit (CPU) exhaustion.

---

## Regex Pitfalls: Deterministic Hazards

- **Catastrophic Backtracking**: Triggered by nested quantifiers (e.g., `(a+)+`), causing exponential match-time.
- **Opacified Syntax**: Incomprehensible expressions hinder peer audit and maintenance.
- **Overgeneral Matching**: Loosely scoped patterns capture unintended input, breaking logic or validation.

---

## Mitigation Protocols (Non-Negotiable)

- **Pattern Audit**: Employ analyzers (e.g., [regex101](https://regex101.com/), [r2d2](https://r2d2.dev/)) to preempt backtracking vectors.
- **Execution Hard Stops**: Enforce processing timeouts or sandbox Regex operations to contain abuse.
- **Precision Engineering**: Opt for exact, minimal-match constructs over greedy wildcards.
- **Engine Selection**: Adopt backtracking-free engines (e.g., Google’s Regular Expression 2 (RE2)) in latency-critical contexts.

---

## Regex: A Dual-Edged Instrument of Security

When deliberately constructed, Regex serves as a **defensive programming asset**. Use cases include:

- **Input Sanitisation**: Strip or validate user inputs to prevent injection vectors such as **Structured Query Language Injection (SQLi)** and **Cross-Site Scripting (XSS)**.
- **Format Enforcement**: Rigorously verify emails, mobile numbers, Universally Unique Identifiers (UUIDs), etc.
- **Intrusion Detection**: Extract threat signatures from access logs and data streams.

> **Caveat**: Regex is not inherently secure. Flawed logic introduces attack surfaces instead of eliminating them.

---

## Final Directive

**Regex is code. Code must be auditable, deterministic, and secure.**  
Never deploy Regex to production without:

- Empirical time testing  
- Readability validation  
- Worst-case complexity analysis  
