# CWE-74 Family View
Name: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')

## Family Summary

The product constructs all or part of a command, data structure, or record using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could...

## Use This Family View When

- only a broad CWE family is known
- you need to choose a more specific child CWE before loading a stage file
- the available CVE metadata is vague or only maps to a parent class

## Children

- `CWE-1236`: Improper Neutralization of Formula Elements in a CSV File (Base)
- `CWE-75`: Failure to Sanitize Special Elements into a Different Plane (Special Element Injection) (Class)
- `CWE-77`: Improper Neutralization of Special Elements used in a Command ('Command Injection') (Class)
- `CWE-78`: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') (Base)
- `CWE-79`: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') (Base)
- `CWE-88`: Improper Neutralization of Argument Delimiters in a Command ('Argument Injection') (Base)
- `CWE-89`: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') (Base)
- `CWE-91`: XML Injection (aka Blind XPath Injection) (Base)
- `CWE-917`: Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection') (Base)
- `CWE-93`: Improper Neutralization of CRLF Sequences ('CRLF Injection') (Base)
- `CWE-94`: Improper Control of Generation of Code ('Code Injection') (Base)
- `CWE-943`: Improper Neutralization of Special Elements in Data Query Logic (Class)
- `CWE-99`: Improper Control of Resource Identifiers ('Resource Injection') (Class)
