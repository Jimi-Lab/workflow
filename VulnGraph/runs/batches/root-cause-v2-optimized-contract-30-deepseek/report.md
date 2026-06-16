# Root Cause v2 Semantic Baseline 10-CVE Report

## Scope

This is a Root Cause Agent semantic baseline. It does not run Judge Agent, SZZ/BIC ranking, or affected-version conversion. Correctness columns are intentionally left for manual review.

## Execution

- Dataset: `E:\AI\Agent\workflow\VulnVersion\DataSet\BaseDataSet_30.json`
- Provider/model: `deepseek/deepseek-v4-pro`
- Command: `run_root_cause_semantic_baseline.py --dataset E:\AI\Agent\workflow\VulnVersion\DataSet\BaseDataSet_30.json --repo-root E:\AI\Agent\workflow\VulnVersion\repo --out-dir runs\batches\root-cause-v2-optimized-contract-30-deepseek --provider-id deepseek --model-id deepseek-v4-pro --timeout 300 --reset --cves CVE-2020-12284 CVE-2020-13904 CVE-2020-14212 CVE-2020-10251 CVE-2020-19667 CVE-2020-25663 CVE-2020-8169 CVE-2020-8177 CVE-2020-8231 CVE-2020-11984 CVE-2020-11985 CVE-2020-11993 CVE-2022-0171 CVE-2022-0185 CVE-2022-0264 CVE-2022-0286 CVE-2022-0322 CVE-2022-0433 CVE-2020-15389 CVE-2020-27814 CVE-2020-27823 CVE-2020-1967 CVE-2020-1971 CVE-2021-23840 CVE-2020-10702 CVE-2020-11869 CVE-2020-11947 CVE-2020-11647 CVE-2020-13164 CVE-2020-15466`
- CVE list: `['CVE-2020-12284', 'CVE-2020-13904', 'CVE-2020-14212', 'CVE-2020-10251', 'CVE-2020-19667', 'CVE-2020-25663', 'CVE-2020-8169', 'CVE-2020-8177', 'CVE-2020-8231', 'CVE-2020-11984', 'CVE-2020-11985', 'CVE-2020-11993', 'CVE-2022-0171', 'CVE-2022-0185', 'CVE-2022-0264', 'CVE-2022-0286', 'CVE-2022-0322', 'CVE-2022-0433', 'CVE-2020-15389', 'CVE-2020-27814', 'CVE-2020-27823', 'CVE-2020-1967', 'CVE-2020-1971', 'CVE-2021-23840', 'CVE-2020-10702', 'CVE-2020-11869', 'CVE-2020-11947', 'CVE-2020-11647', 'CVE-2020-13164', 'CVE-2020-15466']`

## Structural Metrics

- Real OpenCode invocation count: 30
- ingested_raw_count: 27
- structurally_rejected_count: 2
- parse_error_count: 1
- backend_failed_count: 0
- valid_json_count: 29
- fenced_json_count: 28
- empty_message_count: 0
- evidence_backed_hypothesis_count: 27
- invented_id_cases: `[]`
- lint_ingestion_parity_count: 29/30
- multi_fix_gate_coverage: 4/5
- average packet size: 57237.1 bytes
- average evidence trace size: 58617.2 bytes
- average raw response size: 7568.6 bytes
- total duration: 2621.280 seconds

## Seed Result

- Missing CVEs: `[]`
- Patch results: `[{'cve_id': 'CVE-2020-12284', 'repo': 'FFmpeg', 'commit_sha': '1812352d767ccf5431aa440123e2e260a4db2726', 'status': 'ok', 'nodes': 5, 'edges': 4}, {'cve_id': 'CVE-2020-12284', 'repo': 'FFmpeg', 'commit_sha': '838105153a579ff0cea0794afc0275c19c51d3a7', 'status': 'ok', 'nodes': 5, 'edges': 4}, {'cve_id': 'CVE-2020-12284', 'repo': 'FFmpeg', 'commit_sha': 'a3a3730b5456ca00587455004d40c047f7b20a99', 'status': 'ok', 'nodes': 5, 'edges': 4}, {'cve_id': 'CVE-2020-13904', 'repo': 'FFmpeg', 'commit_sha': '8a2ef6d25dc79d472ea7b184c3b95b4658c99838', 'status': 'ok', 'nodes': 7, 'edges': 8}, {'cve_id': 'CVE-2020-13904', 'repo': 'FFmpeg', 'commit_sha': 'd7abedc90443d6bbd7e956fd53d91b343cba50a8', 'status': 'ok', 'nodes': 7, 'edges': 8}, {'cve_id': 'CVE-2020-13904', 'repo': 'FFmpeg', 'commit_sha': '6959358683c7533f586c07a766acc5fe9544d8b2', 'status': 'ok', 'nodes': 7, 'edges': 8}, {'cve_id': 'CVE-2020-13904', 'repo': 'FFmpeg', 'commit_sha': '7dc5dfad31d1bc6cec5f4eb1f9033ce3b715425d', 'status': 'ok', 'nodes': 7, 'edges': 8}, {'cve_id': 'CVE-2020-13904', 'repo': 'FFmpeg', 'commit_sha': '21ce988f98f2399b8919a8a425d467da682a29a7', 'status': 'ok', 'nodes': 7, 'edges': 8}, {'cve_id': 'CVE-2020-13904', 'repo': 'FFmpeg', 'commit_sha': '0f6fa27b241676624bab91fc6ecdf8ac01121d29', 'status': 'ok', 'nodes': 7, 'edges': 8}, {'cve_id': 'CVE-2020-13904', 'repo': 'FFmpeg', 'commit_sha': 'b5e39880fb7269b1b3577cee288e06aa3dc1dfa2', 'status': 'ok', 'nodes': 7, 'edges': 8}, {'cve_id': 'CVE-2020-13904', 'repo': 'FFmpeg', 'commit_sha': '9dfb19baeb86a8bb02c53a441682c6e9a6e104cc', 'status': 'ok', 'nodes': 7, 'edges': 8}, {'cve_id': 'CVE-2020-13904', 'repo': 'FFmpeg', 'commit_sha': 'a3fdeb0c3a4ecabab2c2351b86fc92004526e9cc', 'status': 'ok', 'nodes': 7, 'edges': 8}, {'cve_id': 'CVE-2020-13904', 'repo': 'FFmpeg', 'commit_sha': '57970c41f59319f54879993fc26c55147854c52f', 'status': 'ok', 'nodes': 7, 'edges': 8}, {'cve_id': 'CVE-2020-13904', 'repo': 'FFmpeg', 'commit_sha': 'f80106e256e051082e507496cdaed564adbd4da9', 'status': 'ok', 'nodes': 7, 'edges': 8}, {'cve_id': 'CVE-2020-13904', 'repo': 'FFmpeg', 'commit_sha': '2a5219d359933b4d6a4ccf13e241253543fc390e', 'status': 'ok', 'nodes': 7, 'edges': 8}, {'cve_id': 'CVE-2020-13904', 'repo': 'FFmpeg', 'commit_sha': 'c00e881a450fc465e60f41bd47ea6396a87f3eef', 'status': 'ok', 'nodes': 7, 'edges': 8}, {'cve_id': 'CVE-2020-13904', 'repo': 'FFmpeg', 'commit_sha': 'bd09c9d46c70ef94d34c91f502326853d3f741ab', 'status': 'ok', 'nodes': 7, 'edges': 8}, {'cve_id': 'CVE-2020-13904', 'repo': 'FFmpeg', 'commit_sha': 'c229e5e80f1b67b2120f317e815fec29ca1390a5', 'status': 'ok', 'nodes': 7, 'edges': 8}, {'cve_id': 'CVE-2020-14212', 'repo': 'FFmpeg', 'commit_sha': '0b3bd001ac1745d9d008a2d195817df57d7d1d14', 'status': 'ok', 'nodes': 68, 'edges': 85}, {'cve_id': 'CVE-2020-14212', 'repo': 'FFmpeg', 'commit_sha': 'dd273d359e45ab69398ac0dc41206d5f1a9371bf', 'status': 'ok', 'nodes': 68, 'edges': 85}, {'cve_id': 'CVE-2020-10251', 'repo': 'ImageMagick', 'commit_sha': '868aad754ee599eb7153b84d610f2ecdf7b339f6', 'status': 'ok', 'nodes': 5, 'edges': 4}, {'cve_id': 'CVE-2020-19667', 'repo': 'ImageMagick', 'commit_sha': '5462fd4725018567764c8f66bed98b7ee3e23006', 'status': 'ok', 'nodes': 4, 'edges': 3}, {'cve_id': 'CVE-2020-25663', 'repo': 'ImageMagick', 'commit_sha': 'a47e7a994766b92b10d4a87df8c1c890c8b170f3', 'status': 'ok', 'nodes': 7, 'edges': 8}, {'cve_id': 'CVE-2020-8169', 'repo': 'curl', 'commit_sha': '600a8cded447cd7118ed50142c576567c0cf5158', 'status': 'ok', 'nodes': 10, 'edges': 9}, {'cve_id': 'CVE-2020-8177', 'repo': 'curl', 'commit_sha': '8236aba58542c5f89f1d41ca09d84579efb05e22', 'status': 'ok', 'nodes': 9, 'edges': 8}, {'cve_id': 'CVE-2020-8231', 'repo': 'curl', 'commit_sha': '3c9e021f86872baae412a427e807fbfa2f3e8a22', 'status': 'ok', 'nodes': 32, 'edges': 35}, {'cve_id': 'CVE-2020-11984', 'repo': 'httpd', 'commit_sha': '0c543e3f5b3881d515d6235f152aacaaaf3aba72', 'status': 'ok', 'nodes': 12, 'edges': 15}, {'cve_id': 'CVE-2020-11984', 'repo': 'httpd', 'commit_sha': 'fb08e475bf322f081665fa6f9d9e346136df9337', 'status': 'ok', 'nodes': 12, 'edges': 15}, {'cve_id': 'CVE-2020-11985', 'repo': 'httpd', 'commit_sha': 'd0c4af10ab713734de906b5634cfc15cd370fdf4', 'status': 'ok', 'nodes': 11, 'edges': 10}, {'cve_id': 'CVE-2020-11993', 'repo': 'httpd', 'commit_sha': '63a0a87efa0925514d15c211b508f6594669888c', 'status': 'ok', 'nodes': 298, 'edges': 415}, {'cve_id': 'CVE-2020-11993', 'repo': 'httpd', 'commit_sha': '971fc8f5b5d664ddeb5d22f8adef2137c7980fc7', 'status': 'ok', 'nodes': 44, 'edges': 57}, {'cve_id': 'CVE-2022-0171', 'repo': 'linux', 'commit_sha': '683412ccf61294d727ead4a73d97397396e69a6b', 'status': 'ok', 'nodes': 61, 'edges': 70}, {'cve_id': 'CVE-2022-0185', 'repo': 'linux', 'commit_sha': '722d94847de29310e8aa03fcbdb41fc92c521756', 'status': 'ok', 'nodes': 5, 'edges': 4}, {'cve_id': 'CVE-2022-0264', 'repo': 'linux', 'commit_sha': '7d3baf0afa3aa9102d6a521a8e4c41888bb79882', 'status': 'ok', 'nodes': 5, 'edges': 4}, {'cve_id': 'CVE-2022-0286', 'repo': 'linux', 'commit_sha': '105cd17a866017b45f3c45901b394c711c97bf40', 'status': 'ok', 'nodes': 5, 'edges': 4}, {'cve_id': 'CVE-2022-0322', 'repo': 'linux', 'commit_sha': 'a2d859e3fc97e79d907761550dbc03ff1b36479c', 'status': 'ok', 'nodes': 5, 'edges': 4}, {'cve_id': 'CVE-2022-0433', 'repo': 'linux', 'commit_sha': '3ccdcee28415c4226de05438b4d89eb5514edf73', 'status': 'ok', 'nodes': 7, 'edges': 7}, {'cve_id': 'CVE-2020-15389', 'repo': 'openjpeg', 'commit_sha': 'e8e258ab049240c2dd1f1051b4e773b21e2d3dc0', 'status': 'ok', 'nodes': 7, 'edges': 8}, {'cve_id': 'CVE-2020-27814', 'repo': 'openjpeg', 'commit_sha': '43dd9ee17894a22fa3df88b1e561274632d9ab43', 'status': 'ok', 'nodes': 1, 'edges': 0}, {'cve_id': 'CVE-2020-27823', 'repo': 'openjpeg', 'commit_sha': 'b2072402b7e14d22bba6fb8cde2a1e9996e9a919', 'status': 'ok', 'nodes': 5, 'edges': 4}, {'cve_id': 'CVE-2020-1967', 'repo': 'openssl', 'commit_sha': 'eb563247aef3e83dda7679c43f9649270462e5b1', 'status': 'ok', 'nodes': 5, 'edges': 4}, {'cve_id': 'CVE-2020-1971', 'repo': 'openssl', 'commit_sha': 'f960d81215ebf3f65e03d4d5d857fb9b666d6920', 'status': 'ok', 'nodes': 14, 'edges': 16}, {'cve_id': 'CVE-2021-23840', 'repo': 'openssl', 'commit_sha': '6a51b9e1d0cf0bf8515f7201b68fb0a3482b3dc1', 'status': 'ok', 'nodes': 27, 'edges': 32}, {'cve_id': 'CVE-2020-10702', 'repo': 'qemu', 'commit_sha': 'de0b1bae6461f67243282555475f88b2384a1eb9', 'status': 'ok', 'nodes': 8, 'edges': 8}, {'cve_id': 'CVE-2020-11869', 'repo': 'qemu', 'commit_sha': 'ac2071c3791b67fc7af78b8ceb320c01ca1b5df7', 'status': 'ok', 'nodes': 11, 'edges': 16}, {'cve_id': 'CVE-2020-11947', 'repo': 'qemu', 'commit_sha': 'ff0507c239a246fd7215b31c5658fc6a3ee1e4c5', 'status': 'ok', 'nodes': 5, 'edges': 4}, {'cve_id': 'CVE-2020-11647', 'repo': 'wireshark', 'commit_sha': '6f56fc9496db158218243ea87e3660c874a0bab0', 'status': 'ok', 'nodes': 16, 'edges': 21}, {'cve_id': 'CVE-2020-13164', 'repo': 'wireshark', 'commit_sha': 'e6e98eab8e5e0bbc982cfdc808f2469d7cab6c5a', 'status': 'ok', 'nodes': 22, 'edges': 30}, {'cve_id': 'CVE-2020-15466', 'repo': 'wireshark', 'commit_sha': '11f40896b696e4e8c7f8b2ad96028404a83a51a4', 'status': 'ok', 'nodes': 5, 'edges': 4}]`

## Per-CVE Status

| CVE | Repo | Status | JSON | Contract OK | Ingested Raw | Hypotheses | Evidence-backed | Fix Commits | Multi-fix Mapping | Errors |
| --- | --- | --- | --- | --- | ---: | ---: | ---: | ---: | --- | --- |
| CVE-2020-12284 | FFmpeg | ingested_raw | fenced_json | True | 1 | 1 | 1 | 3 | True |  |
| CVE-2020-13904 | FFmpeg | rejected | fenced_json | False | 0 | 2 | 0 | 15 | False | no declared fix set has complete gated CodeAnchor coverage: ['CVE-2020-13904:fix-set:1'] |
| CVE-2020-14212 | FFmpeg | ingested_raw | fenced_json | True | 1 | 1 | 1 | 2 | True |  |
| CVE-2020-10251 | ImageMagick | ingested_raw | fenced_json | True | 1 | 1 | 1 | 1 | None |  |
| CVE-2020-19667 | ImageMagick | parse_error | malformed | False | 0 | 0 | 0 | 1 | None | assistant output does not contain a JSON object |
| CVE-2020-25663 | ImageMagick | ingested_raw | fenced_json | True | 1 | 1 | 1 | 1 | None |  |
| CVE-2020-8169 | curl | ingested_raw | fenced_json | True | 1 | 1 | 1 | 1 | None |  |
| CVE-2020-8177 | curl | ingested_raw | fenced_json | True | 1 | 1 | 1 | 1 | None |  |
| CVE-2020-8231 | curl | ingested_raw | fenced_json | True | 1 | 1 | 1 | 1 | None |  |
| CVE-2020-11984 | httpd | ingested_raw | fenced_json | True | 1 | 1 | 1 | 2 | True |  |
| CVE-2020-11985 | httpd | ingested_raw | fenced_json | True | 1 | 1 | 1 | 1 | None |  |
| CVE-2020-11993 | httpd | ingested_raw | fenced_json | True | 1 | 1 | 1 | 2 | True |  |
| CVE-2022-0171 | linux | ingested_raw | fenced_json | True | 1 | 1 | 1 | 1 | None |  |
| CVE-2022-0185 | linux | ingested_raw | fenced_json | True | 1 | 1 | 1 | 1 | None |  |
| CVE-2022-0264 | linux | ingested_raw | fenced_json | True | 1 | 1 | 1 | 1 | None |  |
| CVE-2022-0286 | linux | ingested_raw | fenced_json | True | 1 | 1 | 1 | 1 | None |  |
| CVE-2022-0322 | linux | ingested_raw | fenced_json | True | 1 | 1 | 1 | 1 | None |  |
| CVE-2022-0433 | linux | ingested_raw | fenced_json | True | 1 | 1 | 1 | 1 | None |  |
| CVE-2020-15389 | openjpeg | ingested_raw | fenced_json | True | 1 | 1 | 1 | 1 | None |  |
| CVE-2020-27814 | openjpeg | rejected | json | False | 0 | 1 | 0 | 1 | None | GitObservation obs-git-show-unified-43dd9ee17894 is not trusted: ['observation valid_evidence is not true']; hypothesis hyp-001 references rejected anchor_id: ca-001; hypothesis hyp-001 references rejected vulnerable_predicate_id: vp-001; hypothesis hyp-001 references rejected fix_predicate_id: fp-001; no declared fix set has complete gated CodeAnchor coverage: ['CVE-2020-27814:fix-set:1'] |
| CVE-2020-27823 | openjpeg | ingested_raw | fenced_json | True | 1 | 1 | 1 | 1 | None |  |
| CVE-2020-1967 | openssl | ingested_raw | fenced_json | True | 1 | 1 | 1 | 1 | None |  |
| CVE-2020-1971 | openssl | ingested_raw | fenced_json | True | 1 | 1 | 1 | 1 | None |  |
| CVE-2021-23840 | openssl | ingested_raw | fenced_json | True | 1 | 1 | 1 | 1 | None |  |
| CVE-2020-10702 | qemu | ingested_raw | fenced_json | True | 1 | 1 | 1 | 1 | None |  |
| CVE-2020-11869 | qemu | ingested_raw | fenced_json | True | 1 | 1 | 1 | 1 | None |  |
| CVE-2020-11947 | qemu | ingested_raw | fenced_json | True | 1 | 1 | 1 | 1 | None |  |
| CVE-2020-11647 | wireshark | ingested_raw | fenced_json | True | 1 | 1 | 1 | 1 | None |  |
| CVE-2020-13164 | wireshark | ingested_raw | fenced_json | True | 1 | 1 | 1 | 1 | None |  |
| CVE-2020-15466 | wireshark | ingested_raw | fenced_json | True | 1 | 1 | 1 | 1 | None |  |

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
      "count": 1,
      "cases": [
        {
          "cve_id": "CVE-2020-19667",
          "reason": "assistant output does not contain a JSON object"
        }
      ]
    },
    "schema_contract": {
      "count": 2,
      "cases": [
        {
          "cve_id": "CVE-2020-13904",
          "reason": "no declared fix set has complete gated CodeAnchor coverage: ['CVE-2020-13904:fix-set:1']"
        },
        {
          "cve_id": "CVE-2020-27814",
          "reason": "GitObservation obs-git-show-unified-43dd9ee17894 is not trusted: ['observation valid_evidence is not true']; hypothesis hyp-001 references rejected anchor_id: ca-001; hypothesis hyp-001 references rejected vulnerable_predicate_id: vp-001; hypothesis hyp-001 references rejected fix_predicate_id: fp-001; no declared fix set has complete gated CodeAnchor coverage: ['CVE-2020-27814:fix-set:1']"
        }
      ]
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
      "count": 1,
      "cases": [
        {
          "cve_id": "CVE-2020-13904",
          "reason": "accepted anchors did not cover the fix set"
        }
      ]
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
