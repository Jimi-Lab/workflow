# VulnGraph Top-k History Event Judge Packet v1 dev13

本轮只构造可交给 Judge 的 blind/audit packets；未调用模型，未运行 Judge，未运行 converter。

## Stop Gates

- generated_13_of_13: `True`
- blind_packet_forbidden_scan_zero: `True`
- topk_parameterized: `True`
- topk8_recall_at5_not_below_v3: `True`
- cve_2020_11647_not_success_intro: `True`
- cve_2020_19667_not_ordinary_intro: `True`
- audit_label_absent_from_blind: `True`
- no_model_judge_converter_invocation: `True`
- key_events_present: `True`

## Metrics

- cases_total: `13`
- top_k: `8`
- total candidates before/after top-k: `303` / `92`
- target coverage @1/@3/@5/@k: `4` / `8` / `10` / `10`
- blind packet forbidden violations: `0`
- blind packet bytes median/max: `80819` / `150765`

## High Risk Cases

- CVE-2020-19667: score=59, risks={"ambiguous_relocation": 8, "blame_variant_disagreement": 5, "fallback_weak_binding": 8, "feature_series_boundary": 8, "formatting_or_refactor_signal": 4, "invalid_structural_anchor": 8, "no_unique_preliminary_target": 1, "root_or_history_boundary": 8, "whitespace_sensitive": 5}
- CVE-2020-25663: score=44, risks={"ambiguous_relocation": 8, "blame_variant_disagreement": 8, "feature_series_boundary": 8, "formatting_or_refactor_signal": 4, "move_copy_sensitive": 8, "root_or_history_boundary": 8}
- CVE-2020-11647: score=36, risks={"ambiguous_relocation": 5, "blame_variant_disagreement": 6, "formatting_or_refactor_signal": 3, "invalid_structural_anchor": 5, "no_unique_preliminary_target": 1, "not_found_path_missing_or_censored": 6, "whitespace_sensitive": 6}
- CVE-2020-1971: score=27, risks={"blame_variant_disagreement": 8, "fallback_weak_binding": 8, "formatting_or_refactor_signal": 3, "whitespace_sensitive": 8}
- CVE-2020-15389: score=26, risks={"ambiguous_relocation": 6, "blame_variant_disagreement": 8, "formatting_or_refactor_signal": 4, "whitespace_sensitive": 8}

## Key Event Checks

- CVE-2020-8231: in_top_k=True, rank=3, commit=`d021f2e8a0067fc769652f27afec9024c0d02b3d`
- CVE-2020-13904: in_top_k=True, rank=4, commit=`6cc7f1398257d4ffa89f79d52f10b2cabd9ad232`
- CVE-2020-15466: in_top_k=True, rank=1, commit=`1e630b42e1f0573ca549643952017da315e695a0`
- CVE-2022-0286: in_top_k=True, rank=1, commit=`18cb261afd7bf50134e5ccacc5ec91ea16efadd4`
