# P1-A BAPEE Standalone Evaluation

This report is generated before BAPEE is integrated into Step3.

## Summary

- CVEs selected: `8`
- CVEs checked: `8`
- CVEs failed: `0`
- Structural duplicate_expansion_missed lines: `179`
- Evaluation target lines with GT fixed suffix: `16`
- Recovered lines: `0`
- Operational recall: `0.0`
- Silver precision: `None`
- High-confidence recovered lines: `0`
- Manual review cases: `356`
- FN root causes: `{'manual_nonexact_candidates': 8, 'no_equivalent_candidate_with_line_fic': 8}`
- Elapsed seconds: `737.9`

## Per-Repo

| repo | cves | structural target | eval target | recovered | op_recall | silver_precision | failures |
|---|---:|---:|---:|---:|---:|---:|---:|
| FFmpeg | 6 | 159 | 14 | 0 | 0.0 | None | 0 |
| openjpeg | 2 | 20 | 2 | 0 | 0.0 | None | 0 |

## Case Dumps

- `false_positive_cases.jsonl`: accepted recovery whose recovered FIC tag appears in mapped affected versions.
- `false_negative_cases.jsonl`: duplicate_expansion_missed target line not recovered by BAPEE.
- `manual_review_cases.jsonl`: deterministic signals below auto-accept threshold.
