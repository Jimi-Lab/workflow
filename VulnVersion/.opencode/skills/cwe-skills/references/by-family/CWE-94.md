# CWE-94 Family View
Name: Improper Control of Generation of Code ('Code Injection')

## Family Summary

The product constructs all or part of a code segment using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the syntax or...

## Use This Family View When

- only a broad CWE family is known
- you need to choose a more specific child CWE before loading a stage file
- the available CVE metadata is vague or only maps to a parent class

## Children

- `CWE-1336`: Improper Neutralization of Special Elements Used in a Template Engine (Base)
- `CWE-95`: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection') (Variant)
- `CWE-96`: Improper Neutralization of Directives in Statically Saved Code ('Static Code Injection') (Base)
