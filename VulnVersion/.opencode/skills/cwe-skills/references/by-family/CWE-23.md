# CWE-23 Family View
Name: Relative Path Traversal

## Family Summary

The product uses external input to construct a pathname that should be within a restricted directory, but it does not properly neutralize sequences such as ".." that can resolve to a location that is outside of that...

## Use This Family View When

- only a broad CWE family is known
- you need to choose a more specific child CWE before loading a stage file
- the available CVE metadata is vague or only maps to a parent class

## Children

- `CWE-24`: Path Traversal: '../filedir' (Variant)
- `CWE-25`: Path Traversal: '/../filedir' (Variant)
- `CWE-26`: Path Traversal: '/dir/../filename' (Variant)
- `CWE-27`: Path Traversal: 'dir/../../filename' (Variant)
- `CWE-28`: Path Traversal: '..\filedir' (Variant)
- `CWE-29`: Path Traversal: '\..\filename' (Variant)
- `CWE-30`: Path Traversal: '\dir\..\filename' (Variant)
- `CWE-31`: Path Traversal: 'dir\..\..\filename' (Variant)
- `CWE-32`: Path Traversal: '...' (Triple Dot) (Variant)
- `CWE-33`: Path Traversal: '....' (Multiple Dot) (Variant)
- `CWE-34`: Path Traversal: '....//' (Variant)
- `CWE-35`: Path Traversal: '.../...//' (Variant)
