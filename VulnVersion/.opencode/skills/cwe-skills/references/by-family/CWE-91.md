# CWE-91 Family View
Name: XML Injection (aka Blind XPath Injection)

## Family Summary

The product does not properly neutralize special elements that are used in XML, allowing attackers to modify the syntax, content, or commands of the XML before it is processed by an end system.

## Use This Family View When

- only a broad CWE family is known
- you need to choose a more specific child CWE before loading a stage file
- the available CVE metadata is vague or only maps to a parent class

## Children

- `CWE-643`: Improper Neutralization of Data within XPath Expressions ('XPath Injection') (Base)
- `CWE-652`: Improper Neutralization of Data within XQuery Expressions ('XQuery Injection') (Base)
