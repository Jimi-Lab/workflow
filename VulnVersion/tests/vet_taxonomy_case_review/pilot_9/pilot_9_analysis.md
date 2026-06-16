# P1-A pilot_9 运行结果分析

生成时间：2026-05-18

## 1. 运行结论

`pilot_9` 已经证明 P1 case-review 链路可运行，但还不能作为 Step2/Step3 的 admission 依据。

已通过的部分：

- 9 个 repo 全部完成真实 OpenCode review。
- `agent_failed_cases = 0`。
- `review_status_counts = {reviewed: 9}`。
- 必需字段 reload 检查通过。
- 每个 case 都有 root cause summary、fix summary、Theta、Step3 usable evidence。

不能过度解读的部分：

- `reviewed` 不等于证据可直接进入 Step3 hard certificate。
- `cert_fixed_allowed=True` 只是 agent 当前判断，尚未经过 admission simulator。
- `pilot_9` 没覆盖 `del_only`。
- 输出 schema 仍有结构不稳定问题，已在 `review_quality_report.json` 中暴露。

## 2. 运行统计

| 指标 | 数值 |
| --- | ---: |
| planned_cases | 9 |
| completed_cases | 9 |
| agent_failed_cases | 0 |
| needs_manual_review_cases | 0 |
| total_latency_s | 992.548 |
| avg_latency_s | 110.283 |
| max_latency | wireshark / CVE-2020-11647 / 266.969s |

OpenCode：

```text
health = true
version = 1.2.26
provider_id = deepseek
model_id = deepseek-v4-flash
```

## 3. Case 覆盖

| repo | CVE | patch_type | chunks | family | deterministic seed | reviewed archetype |
| --- | --- | --- | ---: | --- | --- | --- |
| FFmpeg | CVE-2020-22019 | add_only | 6 | multi_commit | bounds_length_check | bounds_length_check |
| ImageMagick | CVE-2020-27771 | mixed | 4 | multi_commit | bounds_length_check | bounds_length_check |
| curl | CVE-2024-2379 | add_only | 4 | single_commit | permission_capability_check | permission_capability_check |
| httpd | CVE-2020-11985 | mixed | 3 | single_commit | input_validation_invariant | input_validation_invariant |
| linux | CVE-2022-2602 | add_only | 5 | single_commit | missing_guard_added_validation | missing_guard_added_validation |
| openjpeg | CVE-2020-6851 | add_only | 2 | multi_commit | bounds_length_check | bounds_length_check |
| openssl | CVE-2023-0217 | add_only | 5 | single_commit | null_lifetime_refcount | null_lifetime_refcount |
| qemu | CVE-2020-14394 | add_only | 5 | single_commit | permission_capability_check | missing_resource_limit |
| wireshark | CVE-2020-11647 | add_only | 7 | single_commit | parser_state_or_protocol_invariant | parser_state_or_protocol_invariant |

关键观察：

- qemu / CVE-2020-14394 暴露 deterministic seed 误判：seed 是 `permission_capability_check`，agent 修正为 `missing_resource_limit`。这说明 P1 的价值成立，不能把 deterministic seed 当最终 taxonomy。
- pilot_9 覆盖了 multi-commit，但没有覆盖 `del_only`。P1-B 必须补齐。

## 4. VET 输出质量

VET archetype 分布：

```text
bounds_length_check = 3
input_validation_invariant = 1
missing_guard_added_validation = 1
missing_resource_limit = 1
null_lifetime_refcount = 1
parser_state_or_protocol_invariant = 1
permission_capability_check = 1
```

Certificate policy：

```text
cert_absent_allowed = {False: 9}
cert_fixed_allowed = {False: 6, True: 3}
```

`cert_fixed_allowed=True` 的 case：

- ImageMagick / CVE-2020-27771
- curl / CVE-2024-2379
- qemu / CVE-2020-14394

当前判断：

- 这 3 个只能作为 hard-certificate candidate。
- 不能直接接入 Step3。
- 必须先补 `hard_certificate_candidates` 和 `admission_requirements`，再做 Step3 admission simulator。

## 5. 质量审计发现

新增质量审计产物：

```text
review_quality_report.json
quality_findings.json
```

审计结果：

```text
finding_count = 45
severity_counts = {warn: 45}
step2_admission_ready = false
```

主要问题：

| issue | count | 含义 |
| --- | ---: | --- |
| empty_negative_evidence | 9 | 所有 case 都没有给出明确的 NOT_AFFECTED/FIXED 负证据候选 |
| non_object_source_refs | 8 | 大多数 source_refs 是字符串，不是可机器消费的结构体 |
| non_object_line_risk_signals | 8 | 大多数 line risk signal 是自然语言字符串，不适合直接喂 Step3 |
| reviewed_with_uncertainty | 7 | agent 标记 reviewed，但仍保留 uncertainty |
| empty_forbidden_hard_certificates | 5 | 没明确说明哪些证据禁止作为 hard deletion |
| cert_fixed_without_hard_certificate_candidates | 3 | cert_fixed=True 但缺 hard certificate 候选结构 |
| cert_fixed_without_admission_requirements | 3 | cert_fixed=True 但缺进入 Step3 前的验证条件 |
| cert_fixed_with_uncertainty | 2 | cert_fixed=True 同时存在 uncertainty |

## 6. 针对性加强

已落地的加强：

- `tests/run_vet_case_review_81.py` 新增 `audit_review_quality()`。
- `summary.json` 新增 `quality` 字段。
- `review_quality_report.json` 和 `quality_findings.json` 成为 P1 输出的一部分。
- `review_report.md` 自动显示 quality summary。
- prompt schema 加强：
  - `source_refs` 必须是结构化对象。
  - `line_risk_signals` 必须是结构化对象。
  - `CertificatePolicy` 增加 `hard_certificate_candidates` 和 `admission_requirements`。
  - 要求列出 `forbidden_hard_certificates`。
  - 要求填充 `negative_evidence` 或说明为什么不安全。
  - `reviewed` 状态不能带未解决的 root-cause/certificate uncertainty。

已验证：

```text
python -m pytest tests\test_vet_case_review_runner.py -q
3 passed
```

## 7. P1-B 前必须修正的点

P1-B 不应直接沿用 pilot_9 的宽松输出标准。必须使用已加强的 runner/prompt 重新跑。

P1-B 重点：

- 补齐 `del_only` case。
- 加入更多 deterministic seed 低置信 case。
- 对 `cert_fixed_allowed=True` 的输出强制要求：
  - `hard_certificate_candidates` 非空。
  - `admission_requirements` 非空。
  - 每个 candidate 有结构化 source_refs。
- 对 `source_refs` 做机器可消费格式统一。
- 对 `line_risk_signals` 做机器可消费格式统一。
- 如果存在 certificate uncertainty，不允许只输出 `reviewed`，必须输出 `partial` 或 `needs_manual_review`。

## 8. 当前结论

P1-A 的价值在于验证了真实 agent case-review pipeline 可运行，并暴露了 Step2 admission 所需的结构化缺口。

当前不能进入 Step2 hard-certificate 主路径。

当前下一步是 P1-B `expanded_27`，用加强后的 prompt/schema 重新生成更稳定的 VET taxonomy 样本。
