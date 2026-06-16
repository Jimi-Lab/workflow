# CWE-89 Family View
Name: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

## Family Summary

The product constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended...

## Use This Family View When

- only a broad CWE family is known
- you need to choose a more specific child CWE before loading a stage file
- the available CVE metadata is vague or only maps to a parent class

## Children

- `CWE-564`: SQL Injection: Hibernate (Variant)
