# CWE-22 Family View
Name: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

## Family Summary

The product uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory, but the product does not properly neutralize special...

## Use This Family View When

- only a broad CWE family is known
- you need to choose a more specific child CWE before loading a stage file
- the available CVE metadata is vague or only maps to a parent class

## Children

- `CWE-23`: Relative Path Traversal (Base)
- `CWE-36`: Absolute Path Traversal (Base)
