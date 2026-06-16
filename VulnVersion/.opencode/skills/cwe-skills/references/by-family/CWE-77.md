# CWE-77 Family View
Name: Improper Neutralization of Special Elements used in a Command ('Command Injection')

## Family Summary

The product constructs all or part of a command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended command...

## Use This Family View When

- only a broad CWE family is known
- you need to choose a more specific child CWE before loading a stage file
- the available CVE metadata is vague or only maps to a parent class

## Children

- `CWE-1427`: Improper Neutralization of Input Used for LLM Prompting (Base)
- `CWE-624`: Executable Regular Expression Error (Base)
- `CWE-78`: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') (Base)
- `CWE-88`: Improper Neutralization of Argument Delimiters in a Command ('Argument Injection') (Base)
- `CWE-917`: Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection') (Base)
