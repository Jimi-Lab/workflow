# Detailed SZZ Evidence Expansion v0

This is deterministic local evidence expansion for raw candidate commits. It does not call OpenCode/DeepSeek, does not validate vulnerability-introducing commits, and does not infer formal affected versions.

## Summary

- cases_total: 30
- candidates_total: 61
- strong_candidate_count: 37
- fallback_candidate_count: 24
- evidence_packet_generated_count: 30
- blame_variant_success_rate: 1.0000
- blame_variant_disagreement_count: 18
- line_survives_to_fix_parent_count: 61
- candidate_ancestor_of_fix_count: 61
- move_copy_sensitive_count: 8
- whitespace_sensitive_count: 11
- boundary_candidate_count: 2
- release_reachability_too_broad_count: 25
- lifecycle: raw_candidate

## Required Questions

1. 30 CVE raw candidates all have evidence packets: yes, 30/30 cases generated packets.
2. Blame variants disagree in 18 candidates across cases: `['CVE-2020-10251', 'CVE-2020-11647', 'CVE-2020-11984', 'CVE-2020-11993', 'CVE-2020-15389', 'CVE-2020-15466', 'CVE-2020-19667', 'CVE-2020-1971', 'CVE-2020-25663', 'CVE-2020-8231', 'CVE-2022-0171', 'CVE-2022-0286']`. See `blame_variant_disagreement_report.md`.
3. Candidate lines not surviving to fix parent: 0 candidates `[]`.
4. Move/copy/rename-sensitive candidates: 8 candidates `['CVE-2020-10251', 'CVE-2020-11647', 'CVE-2020-11993', 'CVE-2020-15466', 'CVE-2020-25663', 'CVE-2022-0171', 'CVE-2022-0286']`.
5. Fix-series or backport/equivalent-context hints: 12 candidates `['CVE-2020-10251', 'CVE-2020-11647', 'CVE-2020-11869', 'CVE-2020-11993', 'CVE-2020-15466', 'CVE-2020-19667', 'CVE-2020-1967', 'CVE-2020-27814', 'CVE-2020-8169', 'CVE-2020-8177', 'CVE-2020-8231', 'CVE-2022-0433']`.
6. Highest-risk fallback cases: `['CVE-2020-12284', 'CVE-2020-13904', 'CVE-2020-14212', 'CVE-2020-15466', 'CVE-2020-19667', 'CVE-2020-1971', 'CVE-2020-27814', 'CVE-2020-8169', 'CVE-2022-0433']`; fallback candidates need Judge-side validation before any final claim.
7. Cases suitable for Judge v0 by current deterministic risk screen: 13 cases `['CVE-2020-10702', 'CVE-2020-11869', 'CVE-2020-11984', 'CVE-2020-15389', 'CVE-2020-1967', 'CVE-2020-27823', 'CVE-2020-8177', 'CVE-2020-8231', 'CVE-2021-23840', 'CVE-2022-0171', 'CVE-2022-0185', 'CVE-2022-0264', 'CVE-2022-0286']`.
8. Cases needing manual/rule review before Judge scoring: 22 cases `['CVE-2020-10251', 'CVE-2020-11647', 'CVE-2020-11947', 'CVE-2020-11985', 'CVE-2020-11993', 'CVE-2020-12284', 'CVE-2020-13164', 'CVE-2020-13904', 'CVE-2020-14212', 'CVE-2020-15466', 'CVE-2020-19667', 'CVE-2020-1971', 'CVE-2020-25663', 'CVE-2020-27814', 'CVE-2020-8169', 'CVE-2020-8177', 'CVE-2020-8231', 'CVE-2021-23840', 'CVE-2022-0171', 'CVE-2022-0286', 'CVE-2022-0322', 'CVE-2022-0433']`.

## Release Reachability

- Broad release reachability cases: `['CVE-2020-10251', 'CVE-2020-11647', 'CVE-2020-11947', 'CVE-2020-11985', 'CVE-2020-13164', 'CVE-2020-13904', 'CVE-2020-15466', 'CVE-2020-19667', 'CVE-2020-1971', 'CVE-2020-25663', 'CVE-2020-8177', 'CVE-2020-8231', 'CVE-2021-23840', 'CVE-2022-0322']`.
- Release reachability is emitted as a summary plus `release_reachability_full.json`; it is not a formal version result.

## Artifacts

- Per CVE: `judge_szz_evidence_packet.json`, `szz_evidence_packet.json`, `szz_evidence_audit_packet.json`, `per_candidate_szz_evidence.json`, `release_reachability_full.json`.
- Batch: `summary.json`, `szz_evidence_summary.csv`, `risk_feature_summary.csv`, `release_reachability_summary.csv`, `forbidden_field_scan.json`, `provenance_manifest.json`.

All candidate commits remain `raw_candidate`.
