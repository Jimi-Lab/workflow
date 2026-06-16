# CWE-79 Family View
Name: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

## Family Summary

The product does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.

## Use This Family View When

- only a broad CWE family is known
- you need to choose a more specific child CWE before loading a stage file
- the available CVE metadata is vague or only maps to a parent class

## Children

- `CWE-80`: Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS) (Variant)
- `CWE-81`: Improper Neutralization of Script in an Error Message Web Page (Variant)
- `CWE-83`: Improper Neutralization of Script in Attributes in a Web Page (Variant)
- `CWE-84`: Improper Neutralization of Encoded URI Schemes in a Web Page (Variant)
- `CWE-85`: Doubled Character XSS Manipulations (Variant)
- `CWE-86`: Improper Neutralization of Invalid Characters in Identifiers in Web Pages (Variant)
- `CWE-87`: Improper Neutralization of Alternate XSS Syntax (Variant)
