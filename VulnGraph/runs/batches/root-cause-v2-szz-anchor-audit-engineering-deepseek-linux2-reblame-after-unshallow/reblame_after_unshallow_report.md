# Linux2 Reblame After Unshallow

This run reused existing DeepSeek SZZ handoff artifacts and reran only local parse, contract lint, anchor resolution, blame, and candidate commit aggregation. It did not call OpenCode, did not use fixture output, and did not implement Judge, BIC validation, or affected-version conversion.

## Inputs

- Previous DeepSeek run: `runs/batches/root-cause-v2-szz-anchor-audit-engineering-deepseek-10`
- Root Cause run: `runs/batches/root-cause-v2-optimized-contract-10`
- Dataset: `E:\AI\Agent\workflow\VulnVersion\DataSet\BaseDataSet_30.json`
- Repo root: `E:\AI\Agent\workflow\VulnVersion\repo`
- CVEs: `CVE-2022-0171`, `CVE-2022-0286`

Linux shallow check:

```text
false
```

## Summary

| Metric | Value |
|---|---:|
| Model invocations | 0 |
| Fixture invocations | 0 |
| Cases | 2 |
| Parse success | 2 |
| Contract accepted | 2 |
| Blame evaluable | 2 |
| Censored | 0 |
| Blame success cases | 2 |
| Candidate commit ready cases | 2 |
| Raw candidate commits | 4 |
| Boundary markers | 0 |

## Per-CVE Results

| CVE | Parse | Contract | Anchor retention | Fix commit coverage | Anchors | Blame | Candidate commits | Boundary markers | Errors | Taxonomy |
|---|---|---:|---:|---:|---:|---|---:|---:|---|---|
| CVE-2022-0171 | fenced_json | true | 2/2 | 1/1 | 2 | success | 2 | 0 | none | none |
| CVE-2022-0286 | fenced_json | true | 1/1 | 1/1 | 2 | success | 2 | 0 | none | none |

## Selected Anchors

### CVE-2022-0171

- `modified_old_side` / `control_predecessor`: `virt/kvm/kvm_main.c:581`, fix `683412ccf61294d727ead4a73d97397396e69a6b`
- `modified_old_side` / `sink`: `virt/kvm/kvm_main.c:816`, fix `683412ccf61294d727ead4a73d97397396e69a6b`

Candidate commits:

- `2df72e9bc4c505d8357012f2924589f3d16f9d44`, role `sink`, lifecycle `raw_candidate`, boundary `false`
- `8931a454aea03bab21b3b8fcdc94f674eebd1c5d`, role `control_predecessor`, lifecycle `raw_candidate`, boundary `false`

### CVE-2022-0286

- `add_only_semantic_target` / `state_declaration`: `drivers/net/bonding/bond_main.c:413`, fix `105cd17a866017b45f3c45901b394c711c97bf40`
- `add_only_semantic_target` / `dangerous_use`: `drivers/net/bonding/bond_main.c:414`, fix `105cd17a866017b45f3c45901b394c711c97bf40`

Candidate commits:

- `bdfd2d1fa79acd03e18d1683419572f3682b39fd`, role `dangerous_use`, lifecycle `raw_candidate`, boundary `false`
- `f548a476268d621846bb0146af861bb56250ae37`, role `state_declaration`, lifecycle `raw_candidate`, boundary `false`

## Failure Checks

Because candidate commits were produced for both CVEs, no zero-candidate root-cause diagnosis is needed. The local blame records show:

- `parent_missing`: 0
- `parent_path_missing`: 0
- `parent_line_mismatch`: 0
- `blame_failed`: 0
- `boundary_marker`: 0
- `shallow_history`: 0

All candidate commits remain `raw_candidate`.
