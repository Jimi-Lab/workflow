# P1-A BAPEE Standalone Evaluation

This report is generated before BAPEE is integrated into Step3.

## Summary

- CVEs selected: `3`
- CVEs checked: `3`
- CVEs failed: `0`
- Structural duplicate_expansion_missed lines: `95`
- Evaluation target lines with GT fixed suffix: `8`
- Recovered lines: `8`
- Operational recall: `1.0`
- Silver precision: `1.0`
- High-confidence recovered lines: `8`
- Manual review cases: `38`
- FN root causes: `{}`
- Elapsed seconds: `331.9`

## Per-Repo

| repo | cves | structural target | eval target | recovered | op_recall | silver_precision | failures |
|---|---:|---:|---:|---:|---:|---:|---:|
| FFmpeg | 2 | 51 | 8 | 8 | 1.0 | 1.0 | 0 |
| qemu | 1 | 44 | 0 | 0 | None | None | 0 |

## Case Dumps

- `false_positive_cases.jsonl`: accepted recovery whose recovered FIC tag appears in mapped affected versions.
- `false_negative_cases.jsonl`: duplicate_expansion_missed target line not recovered by BAPEE.
- `manual_review_cases.jsonl`: deterministic signals below auto-accept threshold.
