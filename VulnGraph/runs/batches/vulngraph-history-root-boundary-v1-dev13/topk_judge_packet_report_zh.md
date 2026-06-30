# VulnGraph Top-k History Event Judge Packet v1 dev13

本轮只构造可交给 Judge 的 blind/audit packets；未调用模型，未运行 Judge，未运行 converter。

## Stop Gates

- generated_13_of_13: `False`
- blind_packet_forbidden_scan_zero: `True`
- topk_parameterized: `True`
- topk8_recall_at5_not_below_v3: `True`
- cve_2020_11647_not_success_intro: `True`
- cve_2020_19667_not_ordinary_intro: `True`
- audit_label_absent_from_blind: `True`
- no_model_judge_converter_invocation: `True`
- key_events_present: `True`

## Metrics

- cases_total: `5`
- top_k: `8`
- total candidates before/after top-k: `37` / `37`
- target coverage @1/@3/@5/@k: `2` / `3` / `4` / `4`
- blind packet forbidden violations: `0`
- blind packet bytes median/max: `81696` / `137379`

## High Risk Cases

- CVE-2020-19667: score=54, risks={"ambiguous_relocation": 7, "blame_variant_disagreement": 4, "fallback_weak_binding": 7, "feature_series_boundary": 7, "formatting_or_refactor_signal": 3, "history_root_boundary": 1, "invalid_structural_anchor": 8, "no_unique_preliminary_target": 1, "root_or_history_boundary": 8, "whitespace_sensitive": 4}
- CVE-2020-15466: score=23, risks={"blame_variant_disagreement": 5, "fallback_weak_binding": 5, "formatting_or_refactor_signal": 3, "move_copy_sensitive": 5, "whitespace_sensitive": 5}
- CVE-2022-0286: score=17, risks={"blame_variant_disagreement": 7, "formatting_or_refactor_signal": 3, "move_copy_sensitive": 7}
- CVE-2020-13904: score=14, risks={"fallback_weak_binding": 8, "formatting_or_refactor_signal": 4, "invalid_structural_anchor": 1, "not_found_path_missing_or_censored": 1}
- CVE-2020-8231: score=9, risks={"blame_variant_disagreement": 3, "formatting_or_refactor_signal": 3, "whitespace_sensitive": 3}

## Key Event Checks

- CVE-2020-8231: in_top_k=True, rank=3, commit=`d021f2e8a0067fc769652f27afec9024c0d02b3d`
- CVE-2020-13904: in_top_k=True, rank=4, commit=`6cc7f1398257d4ffa89f79d52f10b2cabd9ad232`
- CVE-2020-15466: in_top_k=True, rank=1, commit=`1e630b42e1f0573ca549643952017da315e695a0`
- CVE-2022-0286: in_top_k=True, rank=1, commit=`18cb261afd7bf50134e5ccacc5ec91ea16efadd4`
