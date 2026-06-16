# CWE-59 Family View
Name: Improper Link Resolution Before File Access ('Link Following')

## Family Summary

The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Use This Family View When

- only a broad CWE family is known
- you need to choose a more specific child CWE before loading a stage file
- the available CVE metadata is vague or only maps to a parent class

## Children

- `CWE-1386`: Insecure Operation on Windows Junction / Mount Point (Base)
- `CWE-61`: UNIX Symbolic Link (Symlink) Following (Compound)
- `CWE-62`: UNIX Hard Link (Variant)
- `CWE-64`: Windows Shortcut Following (.LNK) (Variant)
- `CWE-65`: Windows Hard Link (Variant)
