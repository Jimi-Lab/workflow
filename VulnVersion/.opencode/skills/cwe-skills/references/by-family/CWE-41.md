# CWE-41 Family View
Name: Improper Resolution of Path Equivalence

## Family Summary

The product is vulnerable to file system contents disclosure through path equivalence. Path equivalence involves the use of special characters in file and directory names. The associated manipulations are intended to...

## Use This Family View When

- only a broad CWE family is known
- you need to choose a more specific child CWE before loading a stage file
- the available CVE metadata is vague or only maps to a parent class

## Children

- `CWE-42`: Path Equivalence: 'filename.' (Trailing Dot) (Variant)
- `CWE-44`: Path Equivalence: 'file.name' (Internal Dot) (Variant)
- `CWE-46`: Path Equivalence: 'filename ' (Trailing Space) (Variant)
- `CWE-47`: Path Equivalence: ' filename' (Leading Space) (Variant)
- `CWE-48`: Path Equivalence: 'file name' (Internal Whitespace) (Variant)
- `CWE-49`: Path Equivalence: 'filename/' (Trailing Slash) (Variant)
- `CWE-50`: Path Equivalence: '//multiple/leading/slash' (Variant)
- `CWE-51`: Path Equivalence: '/multiple//internal/slash' (Variant)
- `CWE-52`: Path Equivalence: '/multiple/trailing/slash//' (Variant)
- `CWE-53`: Path Equivalence: '\multiple\\internal\backslash' (Variant)
- `CWE-54`: Path Equivalence: 'filedir\' (Trailing Backslash) (Variant)
- `CWE-55`: Path Equivalence: '/./' (Single Dot Directory) (Variant)
- `CWE-56`: Path Equivalence: 'filedir*' (Wildcard) (Variant)
- `CWE-57`: Path Equivalence: 'fakedir/../realdir/filename' (Variant)
- `CWE-58`: Path Equivalence: Windows 8.3 Filename (Variant)
