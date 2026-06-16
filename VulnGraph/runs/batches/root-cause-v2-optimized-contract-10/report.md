# Root Cause v2 Semantic Baseline 10-CVE Report

## Scope

This is a Root Cause Agent semantic baseline. It does not run Judge Agent, SZZ/BIC ranking, or affected-version conversion. Correctness columns are intentionally left for manual review.

## Execution

- Dataset: `E:\AI\Agent\workflow\VulnVersion\DataSet\BaseDataSet_30.json`
- Provider/model: `google/gemini-2.5-flash`
- Command: `run_root_cause_semantic_baseline.py --dataset E:\AI\Agent\workflow\VulnVersion\DataSet\BaseDataSet_30.json --repo-root E:\AI\Agent\workflow\VulnVersion\repo --out-dir runs\batches\root-cause-v2-optimized-contract-10 --cves CVE-2020-14212 CVE-2020-19667 CVE-2020-8231 CVE-2020-11984 CVE-2022-0171 CVE-2022-0286 CVE-2020-15389 CVE-2020-1967 CVE-2020-11869 CVE-2020-13164 --provider-id google --model-id gemini-2.5-flash --timeout 300 --reset`
- CVE list: `['CVE-2020-14212', 'CVE-2020-19667', 'CVE-2020-8231', 'CVE-2020-11984', 'CVE-2022-0171', 'CVE-2022-0286', 'CVE-2020-15389', 'CVE-2020-1967', 'CVE-2020-11869', 'CVE-2020-13164']`

## Structural Metrics

- Real OpenCode invocation count: 10
- ingested_raw_count: 10
- structurally_rejected_count: 0
- parse_error_count: 0
- backend_failed_count: 0
- valid_json_count: 10
- fenced_json_count: 10
- empty_message_count: 0
- evidence_backed_hypothesis_count: 10
- invented_id_cases: `[]`
- lint_ingestion_parity_count: 10/10
- multi_fix_gate_coverage: 2/2
- average packet size: 53256.5 bytes
- average evidence trace size: 53925.5 bytes
- average raw response size: 7932.6 bytes
- total duration: 290.501 seconds

## Seed Result

- Missing CVEs: `[]`
- Patch results: `[{'cve_id': 'CVE-2020-14212', 'repo': 'FFmpeg', 'commit_sha': '0b3bd001ac1745d9d008a2d195817df57d7d1d14', 'status': 'ok', 'nodes': 68, 'edges': 85}, {'cve_id': 'CVE-2020-14212', 'repo': 'FFmpeg', 'commit_sha': 'dd273d359e45ab69398ac0dc41206d5f1a9371bf', 'status': 'ok', 'nodes': 68, 'edges': 85}, {'cve_id': 'CVE-2020-19667', 'repo': 'ImageMagick', 'commit_sha': '5462fd4725018567764c8f66bed98b7ee3e23006', 'status': 'ok', 'nodes': 4, 'edges': 3}, {'cve_id': 'CVE-2020-8231', 'repo': 'curl', 'commit_sha': '3c9e021f86872baae412a427e807fbfa2f3e8a22', 'status': 'ok', 'nodes': 32, 'edges': 35}, {'cve_id': 'CVE-2020-11984', 'repo': 'httpd', 'commit_sha': '0c543e3f5b3881d515d6235f152aacaaaf3aba72', 'status': 'ok', 'nodes': 12, 'edges': 15}, {'cve_id': 'CVE-2020-11984', 'repo': 'httpd', 'commit_sha': 'fb08e475bf322f081665fa6f9d9e346136df9337', 'status': 'ok', 'nodes': 12, 'edges': 15}, {'cve_id': 'CVE-2022-0171', 'repo': 'linux', 'commit_sha': '683412ccf61294d727ead4a73d97397396e69a6b', 'status': 'ok', 'nodes': 61, 'edges': 70}, {'cve_id': 'CVE-2022-0286', 'repo': 'linux', 'commit_sha': '105cd17a866017b45f3c45901b394c711c97bf40', 'status': 'ok', 'nodes': 5, 'edges': 4}, {'cve_id': 'CVE-2020-15389', 'repo': 'openjpeg', 'commit_sha': 'e8e258ab049240c2dd1f1051b4e773b21e2d3dc0', 'status': 'ok', 'nodes': 7, 'edges': 8}, {'cve_id': 'CVE-2020-1967', 'repo': 'openssl', 'commit_sha': 'eb563247aef3e83dda7679c43f9649270462e5b1', 'status': 'ok', 'nodes': 5, 'edges': 4}, {'cve_id': 'CVE-2020-11869', 'repo': 'qemu', 'commit_sha': 'ac2071c3791b67fc7af78b8ceb320c01ca1b5df7', 'status': 'ok', 'nodes': 11, 'edges': 16}, {'cve_id': 'CVE-2020-13164', 'repo': 'wireshark', 'commit_sha': 'e6e98eab8e5e0bbc982cfdc808f2469d7cab6c5a', 'status': 'ok', 'nodes': 22, 'edges': 30}]`

## Per-CVE Status

| CVE | Repo | Status | JSON | Contract OK | Ingested Raw | Hypotheses | Evidence-backed | Fix Commits | Multi-fix Mapping | Errors |
| --- | --- | --- | --- | --- | ---: | ---: | ---: | ---: | --- | --- |
| CVE-2020-14212 | FFmpeg | ingested_raw | fenced_json | True | 1 | 1 | 1 | 2 | True |  |
| CVE-2020-19667 | ImageMagick | ingested_raw | fenced_json | True | 1 | 1 | 1 | 1 | None |  |
| CVE-2020-8231 | curl | ingested_raw | fenced_json | True | 1 | 1 | 1 | 1 | None |  |
| CVE-2020-11984 | httpd | ingested_raw | fenced_json | True | 1 | 1 | 1 | 2 | True |  |
| CVE-2022-0171 | linux | ingested_raw | fenced_json | True | 1 | 1 | 1 | 1 | None |  |
| CVE-2022-0286 | linux | ingested_raw | fenced_json | True | 1 | 1 | 1 | 1 | None |  |
| CVE-2020-15389 | openjpeg | ingested_raw | fenced_json | True | 1 | 1 | 1 | 1 | None |  |
| CVE-2020-1967 | openssl | ingested_raw | fenced_json | True | 1 | 1 | 1 | 1 | None |  |
| CVE-2020-11869 | qemu | ingested_raw | fenced_json | True | 1 | 1 | 1 | 1 | None |  |
| CVE-2020-13164 | wireshark | ingested_raw | fenced_json | True | 1 | 1 | 1 | 1 | None |  |

## Failure Taxonomy

```json
{
  "categories": {
    "data_import": {
      "count": 0,
      "cases": []
    },
    "patch_extraction": {
      "count": 0,
      "cases": []
    },
    "function_mapping": {
      "count": 0,
      "cases": []
    },
    "evidence_collection": {
      "count": 0,
      "cases": []
    },
    "packet_retrieval": {
      "count": 0,
      "cases": []
    },
    "opencode_backend": {
      "count": 0,
      "cases": []
    },
    "json_parse": {
      "count": 0,
      "cases": []
    },
    "schema_contract": {
      "count": 0,
      "cases": []
    },
    "structural_gate": {
      "count": 0,
      "cases": []
    },
    "anchor_selection": {
      "count": 0,
      "cases": []
    },
    "predicate_generation": {
      "count": 0,
      "cases": []
    },
    "unsupported_inference": {
      "count": 0,
      "cases": []
    },
    "multi_fix_coverage": {
      "count": 0,
      "cases": []
    },
    "semantic_reasoning": {
      "count": 0,
      "cases": []
    },
    "reporting": {
      "count": 0,
      "cases": []
    },
    "other": {
      "count": 0,
      "cases": []
    }
  }
}
```

## Manual Review

Use `evaluation.csv` and `semantic_review_template.md` for semantic labeling. Do not treat `ingested_raw` as semantic correctness.
