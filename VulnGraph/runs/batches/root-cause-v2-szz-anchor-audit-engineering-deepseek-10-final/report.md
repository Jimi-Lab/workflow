# Final 10-CVE SZZ Anchor Audit Engineering Report

This is an engineering-only frozen artifact. It does not validate BICs and does not infer affected versions. All candidate commits remain `raw_candidate`.

## Provenance

- The 10-CVE DeepSeek anchor selections come from `runs/batches/root-cause-v2-szz-anchor-audit-engineering-deepseek-10`.
- `CVE-2022-0171` and `CVE-2022-0286` keep the same model output; only local contract/resolve/blame/candidate artifacts are taken from the Linux reblame run after the repo was unshallowed.
- No OpenCode/DeepSeek call was made while generating this final artifact.
- No fixture output was used.
- No Judge, BIC validation, or affected-version conversion is included.
- Raw candidate commits must not be read as validated BICs.

## Metrics

- cases_total: 10
- parse_success: 10
- contract_ok: 10
- blame_success: 10
- censored_count: 0
- selected_anchor_count: 35
- raw_candidate_commit_count: 23
- root_cause_hunk_retention: 43/43 (1)
- fix_commit_coverage: 12/12 (1)
- invented_ids: []
- taxonomy: {"candidate_inventory_large":{"count":1,"cases":["CVE-2020-13164"]}}

## Per-CVE Summary

| CVE | Parse | Contract | Blame | Anchors | Raw candidate commits | Hunk retention | Fix commit coverage | Source |
|---|---|---:|---|---:|---:|---:|---:|---|
| CVE-2020-14212 | fenced_json | true | success | 4 | 1 | 10/10 | 2/2 | original engineering run |
| CVE-2020-19667 | json | true | success | 1 | 1 | 1/1 | 1/1 | original engineering run |
| CVE-2020-8231 | fenced_json | true | success | 9 | 5 | 9/9 | 1/1 | original engineering run |
| CVE-2020-11984 | fenced_json | true | success | 4 | 3 | 6/6 | 2/2 | original engineering run |
| CVE-2022-0171 | fenced_json | true | success | 2 | 2 | 2/2 | 1/1 | original anchors + linux reblame |
| CVE-2022-0286 | fenced_json | true | success | 2 | 2 | 1/1 | 1/1 | original anchors + linux reblame |
| CVE-2020-15389 | fenced_json | true | success | 5 | 4 | 2/2 | 1/1 | original engineering run |
| CVE-2020-1967 | fenced_json | true | success | 1 | 1 | 1/1 | 1/1 | original engineering run |
| CVE-2020-11869 | fenced_json | true | success | 4 | 2 | 4/4 | 1/1 | original engineering run |
| CVE-2020-13164 | json | true | success | 3 | 2 | 7/7 | 1/1 | original engineering run |

## Per-CVE Candidate Commits

### CVE-2020-14212
- `2558e62713ebc5f3ea22c1a28d8e9cf3249badaf` lifecycle=`raw_candidate`, vote_count=4, roles=`control_predecessor|dangerous_use`, excluded=false

### CVE-2020-19667
- `151b66dffc9e3c2e8c4f8cdaca37ff987ca0f497` lifecycle=`raw_candidate`, vote_count=1, roles=`state_declaration`, excluded=false

### CVE-2020-8231
- `d021f2e8a0067fc769652f27afec9024c0d02b3d` lifecycle=`raw_candidate`, vote_count=4, roles=`dangerous_use|state_declaration`, excluded=false
- `d5bb459ccf1fc5980ae4b95c05b4ecf6454a7599` lifecycle=`raw_candidate`, vote_count=2, roles=`dangerous_use|sink`, excluded=false
- `07cb27c98e92649e74a312faf976271fa7da609c` lifecycle=`raw_candidate`, vote_count=1, roles=`dangerous_use`, excluded=false
- `c43127414d89ccb9ef6517081f68986d991bcfb3` lifecycle=`raw_candidate`, vote_count=1, roles=`propagation`, excluded=false
- `d2b36e466afd69b6e2b202aca21db3bd2e48b190` lifecycle=`raw_candidate`, vote_count=1, roles=`control_predecessor`, excluded=false

### CVE-2020-11984
- `99c59e098103ccf13b833281ec08493e042dfee0` lifecycle=`raw_candidate`, vote_count=2, roles=`propagation|state_declaration`, excluded=false
- `23394f444cc73d6b01af5a8109f79c156a26607c` lifecycle=`raw_candidate`, vote_count=1, roles=`state_declaration`, excluded=false
- `da54e90ddaa01c02a68fda8dc08004c97cb4aa2b` lifecycle=`raw_candidate`, vote_count=1, roles=`propagation`, excluded=false

### CVE-2022-0171
- `2df72e9bc4c505d8357012f2924589f3d16f9d44` lifecycle=`raw_candidate`, vote_count=1, roles=`sink`, excluded=false
- `8931a454aea03bab21b3b8fcdc94f674eebd1c5d` lifecycle=`raw_candidate`, vote_count=1, roles=`control_predecessor`, excluded=false

### CVE-2022-0286
- `bdfd2d1fa79acd03e18d1683419572f3682b39fd` lifecycle=`raw_candidate`, vote_count=1, roles=`dangerous_use`, excluded=false
- `f548a476268d621846bb0146af861bb56250ae37` lifecycle=`raw_candidate`, vote_count=1, roles=`state_declaration`, excluded=false

### CVE-2020-15389
- `055d429ae11ad98dfd3dc68d188ec538588d805c` lifecycle=`raw_candidate`, vote_count=2, roles=`state_declaration`, excluded=false
- `028088f5f077b6cc666f8152736398df68ec239b` lifecycle=`raw_candidate`, vote_count=1, roles=`state_declaration`, excluded=false
- `27e255fa75b7b9e989de3ec379c9de2b7462983b` lifecycle=`raw_candidate`, vote_count=1, roles=`state_declaration`, excluded=false
- `ee0e8a3aadbf56004ff51649cfe5d06cb5c61326` lifecycle=`raw_candidate`, vote_count=1, roles=`control_predecessor`, excluded=false

### CVE-2020-1967
- `604ba26560ca71bf8a1c127da96727b5b2b077e1` lifecycle=`raw_candidate`, vote_count=1, roles=`dangerous_use`, excluded=false

### CVE-2020-11869
- `584acf34cb05f16e13a46d666196a7583d232616` lifecycle=`raw_candidate`, vote_count=2, roles=`state_declaration`, excluded=false
- `862b4a291dcf143fdb227e97feb7fd45e6466aca` lifecycle=`raw_candidate`, vote_count=2, roles=`propagation`, excluded=false

### CVE-2020-13164
- `354b4b74d08fbafe23c7929f1f68eb4c84df4e2f` lifecycle=`raw_candidate`, vote_count=2, roles=`propagation`, excluded=false
- `c38eb2f027ace5a85007fb67084d2fa927467540` lifecycle=`raw_candidate`, vote_count=1, roles=`recursion_entry`, excluded=false

## Artifact Files

- `summary.json`
- `report.md`
- `szz_anchor_audit.csv`
- `manual_anchor_review_template.csv`
- `provenance_manifest.json`
