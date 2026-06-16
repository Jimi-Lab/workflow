# Linux2 SZZ Anchor Audit Engineering Smoke - Blocked

This run did not invoke DeepSeek. The local execution environment rejected the OpenCode/DeepSeek command because the prompts would send workspace and repository-derived data to an external provider.

## Scope

- CVEs requested: `CVE-2022-0171`, `CVE-2022-0286`
- Provider/model requested: `deepseek/deepseek-v4-pro`
- Execution mode requested: `engineering_smoke`
- Formal 10-CVE audit: not run
- Judge/BIC/affected-version: not implemented or run

## Repository Check

```powershell
git -C E:\AI\Agent\workflow\VulnVersion\repo\linux rev-parse --is-shallow-repository
```

Output:

```text
false
```

The Linux repository is no longer shallow.

## Requested Command

```powershell
python scripts\run_root_cause_szz_anchor_audit.py --root-cause-run runs\batches\root-cause-v2-optimized-contract-10 --dataset E:\AI\Agent\workflow\VulnVersion\DataSet\BaseDataSet_30.json --repo-root E:\AI\Agent\workflow\VulnVersion\repo --out-dir runs\batches\root-cause-v2-szz-anchor-audit-engineering-deepseek-linux2-after-unshallow --cves CVE-2022-0171 CVE-2022-0286 --provider-id deepseek --model-id deepseek-v4-pro --timeout 300 --engineering-smoke --top-k-per-patch-family 40 --reset
```

## Blocker

The command was denied before execution. No OpenCode request was sent and no model response was produced.

Unavailable fields:

- `parse_status`
- `contract_ok`
- `root_cause_hunk_retention`
- `fix_commit_coverage`
- `selected anchors`
- `blame_status`
- `candidate_commits`
- `boundary_marker`
- `errors`
- `taxonomy`

Because the smoke never reached candidate generation, `candidate_commits=0` should not be attributed to `shallow_history`, `parent_missing`, `parent_path_missing`, `parent_line_mismatch`, `blame_failed`, `boundary_marker`, or semantic anchor error. The run did not reach those checks.

## Local Verification

- `python -m pytest -q`: `167 passed`
- `python -m compileall -q src tests scripts`: exit code `0`
