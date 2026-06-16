# P1-B expanded_27 运行结果分析

生成时间：2026-05-19

## 1. 运行结论

`expanded_27` 已完成真实 OpenCode case review。

当前状态：

- `planned_cases = 27`
- `completed_cases = 27`
- `agent_failed_cases = 0`
- `review_status_counts = {reviewed: 27}`
- `step2_admission_ready = false`

这说明 P1-B 的 agent 链路已经可用，但 P1-B 输出仍不能直接进入 Step2/Step3 hard-certificate 主路径。

## 2. 断网后的续跑过程

第一次真实运行：

```text
completed_cases = 17
agent_failed_cases = 10
```

失败原因：

- 3 个 case 是 `no json object found`。
- 7 个 case 是网络/证书链异常，例如 `self signed certificate` / `unknown certificate verification error`。

随后新增并验证：

- `--retry-agent-failed`
- fallback JSON repair prompt
- failure session message export

第二次重试：

```text
completed_cases = 24
agent_failed_cases = 3
```

第三次重试：

```text
completed_cases = 27
agent_failed_cases = 0
```

实际 fallback 使用：

```text
fallback_count = 1
fallback_file = qemu__CVE-2021-3544.fallback_prompt.txt
```

## 3. 覆盖情况

patch type 覆盖：

```text
add_only = 7
del_only = 4
mixed = 16
```

fix family：

```text
multi_commit = 10
single_commit = 17
```

deterministic seed 覆盖：

```text
bounds_length_check = 4
input_validation_invariant = 3
missing_guard_added_validation = 1
null_lifetime_refcount = 1
parser_state_or_protocol_invariant = 3
permission_capability_check = 3
status_error_handling_or_logic_correction = 3
unknown_requires_manual_review = 4
unsafe_operation_replacement = 4
vulnerable_branch_removed = 1
```

这比 P1-A 更合理：补齐了 `del_only`，也覆盖了 `unknown_requires_manual_review`、`unsafe_operation_replacement`、`vulnerable_branch_removed` 等 pilot_9 缺失类型。

## 4. Agent-reviewed archetype 分布

```text
bounds_length_check = 3
infinite_loop_bounds_check = 1
input_validation_invariant = 2
loop_bound_missing = 1
loop_boundary_off_by_one = 1
missing_authorization_check = 1
missing_clamp = 1
missing_cleanup = 1
missing_guard_added_validation = 1
null_lifetime_refcount = 1
parser_state_or_protocol_invariant = 3
permission_capability_check = 2
reentrancy_guard_bypass = 1
security_feature_removal_with_logic_correction = 1
status_error_handling_or_logic_correction = 2
unsafe_operation_replacement = 4
vulnerable_branch_removed = 1
```

## 5. Deterministic seed 与 agent-reviewed archetype 偏差

共有 8 个 case 的 agent-reviewed archetype 与 deterministic seed 不一致：

| repo | CVE | deterministic seed | agent-reviewed archetype |
| --- | --- | --- | --- |
| FFmpeg | CVE-2020-20453 | unknown_requires_manual_review | missing_clamp |
| ImageMagick | CVE-2021-39212 | unknown_requires_manual_review | missing_authorization_check |
| httpd | CVE-2020-9490 | status_error_handling_or_logic_correction | security_feature_removal_with_logic_correction |
| openssl | CVE-2022-2097 | unknown_requires_manual_review | loop_boundary_off_by_one |
| qemu | CVE-2020-14394 | permission_capability_check | loop_bound_missing |
| qemu | CVE-2021-3544 | unknown_requires_manual_review | missing_cleanup |
| qemu | CVE-2021-3416 | bounds_length_check | reentrancy_guard_bypass |
| wireshark | CVE-2021-4182 | input_validation_invariant | infinite_loop_bounds_check |

结论：

- deterministic seed 只能作为候选标签，不能作为最终 VET taxonomy。
- Step2 必须允许 agent 重新归类 root-cause archetype。
- Step2 schema 需要容纳更细粒度 archetype，例如 `missing_clamp`、`loop_bound_missing`、`reentrancy_guard_bypass`、`missing_cleanup`。

## 6. Certificate policy 观察

agent 输出：

```text
cert_absent_allowed = {False: 9, True: 18}
cert_fixed_allowed = {False: 2, True: 25}
```

这个比例过高，不能直接采信。

原因：

- 质量审计仍发现大量 `cert_fixed_with_uncertainty`。
- 很多 case 缺少 `negative_evidence`。
- Step3 admission simulator 还没有验证这些 certificate 是否会引入 FN。

结论：

- `cert_absent_allowed=True` 和 `cert_fixed_allowed=True` 当前只能作为 candidate。
- 不能直接进入 Step3 hard deletion / hard NOT_AFFECTED。
- 必须先设计 admission gate：每个 certificate candidate 必须被 GT simulator 和真实小样本验证。

## 7. 质量审计结果

```text
finding_count = 38
severity_counts = {warn: 38}
step2_admission_ready = false
```

issue 分布：

```text
cert_fixed_with_uncertainty = 12
empty_negative_evidence = 12
reviewed_with_uncertainty = 12
empty_line_risk_signals = 2
```

与 P1-A 相比已经改善：

- `non_object_source_refs` 从 8 降到 0。
- `non_object_line_risk_signals` 从 8 降到 0。
- `cert_fixed_without_hard_certificate_candidates` 从 3 降到 0。
- `cert_fixed_without_admission_requirements` 从 3 降到 0。

仍未解决：

- `reviewed` 与 uncertainty 并存。
- `cert_fixed_allowed=True` 与 uncertainty 并存。
- `negative_evidence` 不足。

## 8. 对 Step2 的直接要求

P1-B 说明 Step2 必须做两层输出：

1. `reviewed_vet`
   - root-cause taxonomy
   - vulnerable condition
   - fix evidence
   - guards

2. `admission_evidence`
   - hard certificate candidates
   - priority-only evidence
   - forbidden hard certificates
   - negative evidence
   - uncertainty
   - admission requirements

Step2 不能把 `cert_fixed_allowed=True` 直接下发给 Step3。Step3 只能使用通过 admission gate 的 evidence。

## 9. 下一步

优先级：

1. 根据 P1-B 的 27 个 case 修改 `step2.md` 和 Step2 schema。
2. 把 `cert_fixed_with_uncertainty` 视为 admission blocker。
3. 设计 `simulate_vet_admission_gate.py`，验证 certificate candidate 是否会降低 recall。
4. 再决定是否跑 P1-C full_81。

当前不建议立即接 Step3 主流程。
