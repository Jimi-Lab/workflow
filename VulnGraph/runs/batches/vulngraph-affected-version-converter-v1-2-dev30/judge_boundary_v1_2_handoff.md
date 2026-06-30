# VulnGraph Judge Boundary v1.2 Handoff

## Scope

- Development set only: `BaseDataSet_30.json`.
- No 100-CVE run, Neo4j, attacker-perspective module, or GT in blind/model input.
- History events and selected boundaries remain raw candidates, not validated BICs.

## Architecture

1. Distinct normal, `-w`, `-M`, and `-C` blame SHAs become wrapper-owned `HistoryEventCandidate` objects.
2. Frozen candidate-inventory fallback lines are accepted only after parent path, line, text, and SHA-256 verification.
3. Branch contexts are derived from Git ancestry, merge-base, containing refs, fix lineage, and stable patch-id.
4. Judge v1.2 accounts every history event exactly once. Release-breadth features are absent from boundary input.
5. Converter v1.2 propagates state independently per branch context and verifies old-line survival.
6. Uncertain selection is reported as `unresolved_boundary`; it is not a converted empty prediction.

## Commands

```powershell
python scripts\run_judge_boundary_v1_2.py --out-dir runs\batches\vulngraph-judge-boundary-v1-2-targeted-deepseek --cves CVE-2020-11984 CVE-2020-11647 CVE-2020-8231 CVE-2020-12284 CVE-2020-14212 CVE-2020-13164 CVE-2021-23840 --provider-id deepseek --model-id deepseek-v4-pro --timeout 300 --repair-retries 1 --reset

python scripts\run_judge_boundary_v1_2.py --out-dir runs\batches\vulngraph-judge-boundary-v1-2-dev30 --provider-id deepseek --model-id deepseek-v4-pro --timeout 300 --repair-retries 1 --reset

python scripts\run_affected_version_converter_v1_2.py --boundary-run runs\batches\vulngraph-judge-boundary-v1-2-dev30 --out-dir runs\batches\vulngraph-affected-version-converter-v1-2-dev30 --reset

python -m pytest -q
python -m compileall -q src tests scripts
```

## Judge Results

- Provider/model: `deepseek/deepseek-v4-pro` through OpenCode.
- Dev30 parse: 30/30.
- Dev30 contract: 30/30 after one isolated rerun of CVE-2020-15466; its first rejected attempt is retained under `attempts/`.
- Candidate accounting: 102/102.
- Dev30 model invocations: 41.
- Dev30 model prompt bytes: 906,737.
- Current targeted run: 12 invocations and 328,932 model prompt bytes.
- Actual calls made during this task: 65, including a superseded 12-call targeted run before release-risk input cleanup. Its base prompt bytes were 176,151; repair prompt bytes were overwritten by the required reset and are not recoverable from the final directory.

## Converter Results

| Metric | v1.1 | v1.2 | Raw top1 artifact recompute |
|---|---:|---:|---:|
| Exact | 8/30 | 10/30 | 15/30 |
| NMR | 0.333333 | 0.466667 | 0.733333 |
| Micro precision | 0.713217 | 0.746281 | 0.610344 |
| Micro recall | 0.283589 | 0.447695 | 0.854239 |
| Micro F1 | 0.405818 | 0.559653 | 0.711983 |
| TP / FP / FN | 572 / 230 / 1445 | 903 / 307 / 1114 | 1723 / 1100 / 294 |

The stated advancement baseline was Exact 15/30 and micro F1 0.704872. v1.2 reaches only Exact 10/30 and F1 0.559653, so the gate fails. The current raw-top1 artifact recomputes to F1 0.711983; both values are retained rather than silently conflated.

## Status Attribution

- Converted: 23.
- Unresolved boundary: 7.
- Unknown state: 0.
- Blocked: 0.
- Unresolved cases: CVE-2020-12284, CVE-2020-15466, CVE-2020-19667, CVE-2020-1971, CVE-2020-27814, CVE-2022-0171, CVE-2022-0433.
- False-positive-heavy: CVE-2020-10251, CVE-2020-13904, CVE-2020-14212, CVE-2021-23840.
- False-negative-heavy: 9 cases; see `stage_error_attribution.json`.

Diagnostic group F1:

- Strong: 0.662669.
- Fallback: 0.391517.
- Modify/delete: 0.882150.
- Add-only: 0.439799.
- Selected/converted cases: 0.682282.
- Unresolved cases: 0.0, scored as empty predictions in all-case metrics.

## Targeted Regressions

- CVE-2020-11984: two branch contexts; prediction restored to 14 maintenance releases instead of empty.
- CVE-2020-11647: blame-variant SHA alternatives materialized.
- CVE-2020-8231: normal/whitespace disagreement materialized and auditable.
- CVE-2020-12284 and CVE-2020-14212: brace/declaration noise removed; verified fallback inventory lines retained.
- CVE-2020-14212: both fix commits independently represented.
- CVE-2020-13164: remains FP-heavy and requires branch-state refinement.
- CVE-2021-23840: add-only protected-old-code events retained.

## Verification

- `python -m pytest -q`: 272 passed.
- `python -m compileall -q src tests scripts`: exit code 0.
- Blind input forbidden exact-key violations: 0.
- Targeted deterministic regression report: passed.

## Remaining Blockers

1. Judge over-abstention leaves 7 cases unresolved and contributes 580 false-negative versions.
2. Add-only/fallback state precision remains weak.
3. Some selected old lines do not survive across all semantically equivalent release branches, reducing recall.
4. Branch-local equivalent-fix discovery currently relies on available refs and stable patch-id; semantic equivalents with changed patch-id remain under-modeled.
5. The dev30 advancement gate failed. Per protocol, 100-CVE validation was not run.
