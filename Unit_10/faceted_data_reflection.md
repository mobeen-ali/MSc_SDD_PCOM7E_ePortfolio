# 🧩 Faceted Data Reflection (Based on Schmitz et al., 2016)

## ❓ Is Faceted Data a Good Approach to Prevent Data Leakage?

Yes, faceted data can be an effective strategy to mitigate data leakage risks, especially in systems where information must be dynamically filtered based on **security context** (e.g., user role, location, device). Instead of creating multiple system versions or complex conditional logic, faceted execution allows a single program to generate **multiple views** of the same data, each tailored to a user's privilege level.

---

## ✅ Advantages

- **Security by Design**: Prevents unauthorized access programmatically by default.
- **Separation of Concerns**: Developers can specify high/low confidentiality logic in parallel.
- **Dynamic Policy Enforcement**: Access control decisions happen during execution based on current user context.

---

## ❌ Disadvantages

- **Complexity**: Debugging and reasoning about multi-faceted flows can be difficult.
- **Performance**: Running faceted execution branches may impact speed and memory.
- **Tooling Gaps**: Limited Python-native frameworks to support full faceted execution models.

---

## 💡 Python Implementation Outline

While Python lacks full-fledged faceted data engines, a simplified model might look like this:

```python
class FacetedValue:
    def __init__(self, public, private):
        self.public = public
        self.private = private

    def resolve(self, is_admin):
        return self.private if is_admin else self.public

# Usage
data = FacetedValue(public="Redacted Info", private="Sensitive Report")
print(data.resolve(is_admin=False))  # Outputs: Redacted Info
print(data.resolve(is_admin=True))   # Outputs: Sensitive Report
```