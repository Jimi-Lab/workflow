# CWE-93 Family View
Name: Improper Neutralization of CRLF Sequences ('CRLF Injection')

## Family Summary

The product uses CRLF (carriage return line feeds) as a special element, e.g. to separate lines or records, but it does not neutralize or incorrectly neutralizes CRLF sequences from inputs.

## Use This Family View When

- only a broad CWE family is known
- you need to choose a more specific child CWE before loading a stage file
- the available CVE metadata is vague or only maps to a parent class

## Children

- `CWE-113`: Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Request/Response Splitting') (Variant)
