# P1-A BAPEE Standalone Evaluation

This report is generated before BAPEE is integrated into Step3.

## Summary

- CVEs selected: `5`
- CVEs checked: `5`
- CVEs failed: `0`
- Structural duplicate_expansion_missed lines: `107`
- Evaluation target lines with GT fixed suffix: `11`
- Recovered lines: `0`
- Operational recall: `0.0`
- Silver precision: `None`
- High-confidence recovered lines: `0`
- Manual review cases: `464`
- FN root causes: `{'manual_nonexact_candidates': 7, 'no_equivalent_candidate_with_line_fic': 3, 'multi_commit_semantics_or_missing_component': 1}`
- Elapsed seconds: `995.7`

## Per-Repo

| repo | cves | structural target | eval target | recovered | op_recall | silver_precision | failures |
|---|---:|---:|---:|---:|---:|---:|---:|
| FFmpeg | 3 | 81 | 10 | 0 | 0.0 | None | 0 |
| httpd | 1 | 6 | 1 | 0 | 0.0 | None | 0 |
| wireshark | 1 | 20 | 0 | 0 | None | None | 0 |

## Case Dumps

- `false_positive_cases.jsonl`: accepted recovery whose recovered FIC tag appears in mapped affected versions.
- `false_negative_cases.jsonl`: duplicate_expansion_missed target line not recovered by BAPEE.
- `manual_review_cases.jsonl`: deterministic signals below auto-accept threshold.
