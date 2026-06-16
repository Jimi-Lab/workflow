# P1-A BAPEE Standalone Evaluation

This report is generated before BAPEE is integrated into Step3.

## Summary

- CVEs selected: `100`
- CVEs checked: `100`
- CVEs failed: `0`
- Structural duplicate_expansion_missed lines: `2045`
- Evaluation target lines with GT fixed suffix: `30`
- Recovered lines: `8`
- Operational recall: `0.26666666666666666`
- Silver precision: `1.0`
- High-confidence recovered lines: `8`
- Manual review cases: `522`
- FN root causes: `{'multi_commit_semantics_or_missing_component': 1, 'no_equivalent_candidate_with_line_fic': 16, 'manual_nonexact_candidates': 5}`
- Elapsed seconds: `4528.5`

## Per-Repo

| repo | cves | structural target | eval target | recovered | op_recall | silver_precision | failures |
|---|---:|---:|---:|---:|---:|---:|---:|
| FFmpeg | 47 | 1126 | 27 | 8 | 0.2962962962962963 | 1.0 | 0 |
| ImageMagick | 6 | 1 | 0 | 0 | None | None | 0 |
| curl | 6 | 0 | 0 | 0 | None | None | 0 |
| httpd | 12 | 36 | 1 | 0 | 0.0 | None | 0 |
| linux | 5 | 290 | 0 | 0 | None | None | 0 |
| openjpeg | 5 | 50 | 2 | 0 | 0.0 | None | 0 |
| openssl | 5 | 60 | 0 | 0 | None | None | 0 |
| qemu | 9 | 391 | 0 | 0 | None | None | 0 |
| wireshark | 5 | 91 | 0 | 0 | None | None | 0 |

## Case Dumps

- `false_positive_cases.jsonl`: accepted recovery whose recovered FIC tag appears in mapped affected versions.
- `false_negative_cases.jsonl`: duplicate_expansion_missed target line not recovered by BAPEE.
- `manual_review_cases.jsonl`: deterministic signals below auto-accept threshold.
