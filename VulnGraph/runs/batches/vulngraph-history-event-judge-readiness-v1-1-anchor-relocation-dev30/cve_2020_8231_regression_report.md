# CVE-2020-8231 Anchor Relocation Regression

The old absolute line is treated only as a hint. A found context now requires relocated text/hash or diff evidence.

- `pre-fix-line:58fa8338ad3ea672acd04e48ca778e35489ce37c52567992e431acf7f5bd245a` parent: old `<unavailable>` -> new `absent_by_event` `<none>:-` `diff_hunk_mapped` `<unavailable>`
- `pre-fix-line:58fa8338ad3ea672acd04e48ca778e35489ce37c52567992e431acf7f5bd245a` candidate: old `<unavailable>` -> new `found` `lib/connect.c:1135` `exact_hash` `    struct connectdata *c = data->state.lastconnect;`
- `pre-fix-line:96e2823d262eba5fab1e424346eba3b286e2e1397a371c9d9f8e0cbfdd8a56b8` parent: old `    /* When this handle gets removed, other handles may be able to get the` -> new `found` `lib/multi.c:627` `exact_hash` `      data->state.lastconnect = conn;`
- `pre-fix-line:96e2823d262eba5fab1e424346eba3b286e2e1397a371c9d9f8e0cbfdd8a56b8` candidate: old `<unavailable>` -> new `found` `lib/multi.c:605` `exact_hash` `      data->state.lastconnect = conn;`

- Candidate summaries: 2
