# CWE-36 Family View
Name: Absolute Path Traversal

## Family Summary

The product uses external input to construct a pathname that should be within a restricted directory, but it does not properly neutralize absolute path sequences such as "/abs/path" that can resolve to a location that...

## Use This Family View When

- only a broad CWE family is known
- you need to choose a more specific child CWE before loading a stage file
- the available CVE metadata is vague or only maps to a parent class

## Children

- `CWE-37`: Path Traversal: '/absolute/pathname/here' (Variant)
- `CWE-38`: Path Traversal: '\absolute\pathname\here' (Variant)
- `CWE-39`: Path Traversal: 'C:dirname' (Variant)
- `CWE-40`: Path Traversal: '\\UNC\share\name\' (Windows UNC Share) (Variant)
