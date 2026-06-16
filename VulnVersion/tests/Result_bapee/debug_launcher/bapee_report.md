# P1-A BAPEE Standalone Evaluation

This report is generated before BAPEE is integrated into Step3.

## Summary

- CVEs selected: `1`
- CVEs checked: `1`
- CVEs failed: `0`
- Structural duplicate_expansion_missed lines: `25`
- Evaluation target lines with GT fixed suffix: `0`
- Recovered lines: `0`
- Operational recall: `None`
- Silver precision: `None`
- High-confidence recovered lines: `0`
- Manual review cases: `0`
- FN root causes: `{}`
- Elapsed seconds: `53.5`

## Per-Repo

| repo | cves | structural target | eval target | recovered | op_recall | silver_precision | failures |
|---|---:|---:|---:|---:|---:|---:|---:|
| FFmpeg | 1 | 25 | 0 | 0 | None | None | 0 |

## Case Dumps

- `false_positive_cases.jsonl`: accepted recovery whose recovered FIC tag appears in mapped affected versions.
- `false_negative_cases.jsonl`: duplicate_expansion_missed target line not recovered by BAPEE.
- `manual_review_cases.jsonl`: deterministic signals below auto-accept threshold.
