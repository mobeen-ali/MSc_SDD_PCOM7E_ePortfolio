# Faceted Data Reflection (Based on Schmitz et al., 2016)

## Applicability of the Faceted Data Model for Preventing Information Leakage

The faceted data model, as proposed by Schmitz et al. (2016), offers a programmatic mechanism for enforcing dynamic, context-aware data access. It enables a single execution context to yield multiple views of the same data, selectively exposed based on the user's security attributes such as role, location, or device integrity. This reduces the risk of unintended disclosure without requiring multiple system variants or deeply nested conditional logic.

## Advantages

- **Security by Design**: Data disclosure is inherently constrained by the access context, reducing exposure by default.
- **Separation of Concerns**: Confidential and non-confidential logic can be cleanly expressed in parallel, supporting maintainable codebases.
- **Dynamic Policy Enforcement**: Runtime decisions allow enforcement of contextual access control without static privilege mappings.

## Disadvantages

- **Implementation Complexity**: Reasoning about control and data flow in a multi-faceted context increases cognitive and debugging overhead.
- **Performance Overhead**: Simultaneous evaluation of multiple execution paths can incur computational and memory penalties.
- **Limited Native Support**: The Python ecosystem lacks mature frameworks to support full-scale faceted execution, requiring manual implementations.

## Simplified Python-Based Implementation

Although native faceted execution frameworks are absent in Python, a minimal abstraction can simulate the behaviour:

```python
class FacetedValue:
    def __init__(self, public, private):
        self.public = public
        self.private = private

    def resolve(self, is_admin):
        return self.private if is_admin else self.public

# Example usage
data = FacetedValue(public="Redacted Info", private="Sensitive Report")
print(data.resolve(is_admin=False))  # Outputs: Redacted Info
print(data.resolve(is_admin=True))   # Outputs: Sensitive Report
```
This example demonstrates how role-based view resolution can be encapsulated in an object, mimicking the core principle of faceted execution.
