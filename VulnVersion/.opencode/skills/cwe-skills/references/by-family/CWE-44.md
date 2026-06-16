# CWE-44 Family View
Name: Path Equivalence: 'file.name' (Internal Dot)

## Family Summary

The product accepts path input in the form of internal dot ('file.ordir') without appropriate validation, which can lead to ambiguous path resolution and allow an attacker to traverse the file system to unintended...

## Use This Family View When

- only a broad CWE family is known
- you need to choose a more specific child CWE before loading a stage file
- the available CVE metadata is vague or only maps to a parent class

## Children

- `CWE-45`: Path Equivalence: 'file...name' (Multiple Internal Dot) (Variant)
