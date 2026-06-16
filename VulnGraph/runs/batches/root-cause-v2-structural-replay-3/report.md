# Root Cause Structural Replay

This replay invokes no Agent and uses no legacy reconstruction adapter. Old parsed output and native wrapper trace are evaluated unchanged against a freshly rebuilt graph.

- Agent invocation count: 0
- Legacy adapter count: 0
- Status counts: `{'rejected': 3}`
- Structural error count: 21
- Lint/ingestion parity: `True`

| CVE | Status | Accepted hypotheses | Rejected hypotheses | Structural errors | Invented IDs | Parity |
| --- | --- | --- | --- | ---: | --- | --- |
| CVE-2020-24020 | rejected | [] | ['hyp:CVE-2020-24020:integer-overflow-in-data-length'] | 9 | ['changed-function:FFmpeg:584f396132aa19d21bb1e38ad9a5d428869290cb:libavfilter/dnn/dnn_backend_native.c:calculate_operand_dims_count'] | True |
| CVE-2022-3109 | rejected | [] | ['hyp:CVE-2022-3109:1'] | 5 | [] | True |
| CVE-2023-47342 | rejected | [] | ['root-cause-hypothesis:CVE-2023-47342:1'] | 7 | [] | True |

## Compatibility Boundary

A rejection of an old artifact is retained as a structural regression finding. The replay does not rewrite stale function IDs or relax the production gate.
