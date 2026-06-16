# CWE-99 Family View
Name: Improper Control of Resource Identifiers ('Resource Injection')

## Family Summary

The product receives input from an upstream component, but it does not restrict or incorrectly restricts the input before it is used as an identifier for a resource that may be outside the intended sphere of control.

## Use This Family View When

- only a broad CWE family is known
- you need to choose a more specific child CWE before loading a stage file
- the available CVE metadata is vague or only maps to a parent class

## Children

- `CWE-641`: Improper Restriction of Names for Files and Other Resources (Base)
- `CWE-694`: Use of Multiple Resources with Duplicate Identifier (Base)
- `CWE-914`: Improper Control of Dynamically-Identified Variables (Base)
