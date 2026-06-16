# P1-A BAPEE Standalone Evaluation

This report is generated before BAPEE is integrated into Step3.

## Summary

- CVEs selected: `1`
- CVEs checked: `1`
- CVEs failed: `0`
- Structural duplicate_expansion_missed lines: `23`
- Evaluation target lines with GT fixed suffix: `2`
- Recovered lines: `2`
- Operational recall: `1.0`
- Silver precision: `1.0`
- High-confidence recovered lines: `2`
- Manual review cases: `10`
- FN root causes: `{}`
- Elapsed seconds: `127.0`

## Per-Repo

| repo | cves | structural target | eval target | recovered | op_recall | silver_precision | failures |
|---|---:|---:|---:|---:|---:|---:|---:|
| FFmpeg | 1 | 23 | 2 | 2 | 1.0 | 1.0 | 0 |

## Case Dumps

- `false_positive_cases.jsonl`: accepted recovery whose recovered FIC tag appears in mapped affected versions.
- `false_negative_cases.jsonl`: duplicate_expansion_missed target line not recovered by BAPEE.
- `manual_review_cases.jsonl`: deterministic signals below auto-accept threshold.
