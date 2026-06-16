# VET Case Review 81 长期维护文档

更新时间：2026-05-19

本文档维护 VulnVersion 的 81 个代表性 CVE VET case review。它不是运行流水账，而是 Step2/Step3 继续迭代时必须遵守的事实、负结果、当前路线和验收门槛。

当前目标：

```text
Step1 complete patch evidence
-> P1/P2 VET case review
-> Step2 reviewed_vet + admission_evidence
-> Admission gate usage labeling
-> Step3 VulnTree line/tag/segment scoring
-> Dynamic scheduler + agent tag judge
```

核心判断：

- Step2 不是冗余模块。Step2 的 VET 质量会直接影响 Step3 的 line/tag 打分、probe 选择和 tag judge 准确率。
- 当前不能继续沿用 certificate-oriented 设计。`cert_absent_allowed / cert_fixed_allowed` 这类字段已经被 P1-B admission 测试证明不安全。
- 下一步应先做 Step2 schema v2 和 `expanded_27_v2`，而不是直接跑 `full_81`。

## 1. 不可变原则

1. 正式数据集统一使用：

```text
E:\AI\Agent\workflow\VulnVersion\DataSet\BaseDataOrder.json
```

2. GT 只允许用于 simulator / final evaluation，不允许进入 Step2 prompt、Step3 planning 或 agent prompt。
3. Step2 agent 负责抽象 root-cause-level VET，不负责判断 affected versions。
4. Step3 agent 只判断 selected tag 的 `AFFECTED / NOT_AFFECTED`，不负责 tag plan。
5. 所有 evidence 默认只能用于 `prompt_context` 或 `priority`。未经 admission 验证，不得进入 hard decision。
6. 不允许把 deterministic seed 当最终 VET taxonomy。
7. 不允许把普通 touched file、普通 token、commit message 直接当 hard certificate。
8. 任何进入 Step3 主流程的新策略，必须先有 1128 CVE simulator 或真实小样本 OpenCode 验证。

## 2. 数据与产物路径

| 项目 | 路径 |
| --- | --- |
| 全量数据集 | `E:\AI\Agent\workflow\VulnVersion\DataSet\BaseDataOrder.json` |
| NVD/CVSS 补充 | `E:\AI\Agent\workflow\VulnVersion\DataSet\BaseData_nvd.json` |
| 81-case dataset | `E:\AI\Agent\workflow\VulnVersion\tests\vet_taxonomy_corpus\BaseDataOrder_vet_case_study_81.json` |
| 81-case selection | `E:\AI\Agent\workflow\VulnVersion\tests\vet_taxonomy_corpus\selected_cases.json` |
| deterministic VET seed | `E:\AI\Agent\workflow\VulnVersion\tests\vet_taxonomy_corpus\vet_archetype_seed.jsonl` |
| Step1 corpus work dir | `E:\AI\Agent\workflow\VulnVersion\tests\vet_taxonomy_corpus\work` |
| P1-A output | `E:\AI\Agent\workflow\VulnVersion\tests\vet_taxonomy_case_review\pilot_9` |
| P1-B output | `E:\AI\Agent\workflow\VulnVersion\tests\vet_taxonomy_case_review\expanded_27` |
| P1-B admission output | `E:\AI\Agent\workflow\VulnVersion\tests\vet_admission_gate_p1b` |
| P1 runner | `E:\AI\Agent\workflow\VulnVersion\tests\run_vet_case_review_81.py` |
| Admission simulator | `E:\AI\Agent\workflow\VulnVersion\tests\simulate_vet_admission_gate.py` |

## 3. 当前已验证事实

### 3.1 81-case corpus

命令：

```powershell
cd E:\AI\Agent\workflow\VulnVersion
python tests\build_vet_taxonomy_corpus.py --target-size 81 --out tests\vet_taxonomy_corpus --force-step1
```

结果：

```text
total_cves = 1128
completed_cves = 1128
failed_cves = 0
selected_cases = 81
```

修复过的关键问题：

- merge commit 默认 `git show --patch --format=` 可能不输出 patch。
- `repo.show_patch()` 已加入 `git show -m --first-parent --patch` fallback。
- `openjpeg / CVE-2020-27814` 能解析到 `l_data_size = 74`。
- `linux / CVE-2022-20568` 能解析到 `PF_IO_WORKER`。
- 修复后全量 patch type 分布中不再出现 `empty_or_merge`。

Step1 相关测试最近结果：

```text
28 passed
```

### 3.2 81-case 覆盖范围

81 个 case 是分层抽样，不是随机抽样。

覆盖维度：

- 9 个 repo：FFmpeg, ImageMagick, curl, httpd, linux, openjpeg, openssl, qemu, wireshark。
- patch type：`add_only`, `del_only`, `mixed`。
- fix family：single-commit 和 multi-commit。
- patch size：small, medium, large。
- 主要 CWE。
- 主要 deterministic VET seed。

deterministic seed 分布：

```text
bounds_length_check = 23
permission_capability_check = 14
null_lifetime_refcount = 8
missing_guard_added_validation = 7
status_error_handling_or_logic_correction = 6
unknown_requires_manual_review = 6
parser_state_or_protocol_invariant = 5
input_validation_invariant = 4
unsafe_operation_replacement = 4
vulnerable_branch_removed = 4
```

这些只是 seed，不是最终 taxonomy。

## 4. P1-A / P1-B 实测结论

### 4.1 P1-A `pilot_9`

目的：验证 prompt、schema、artifact、OpenCode agent 可用性。

结果：

```text
planned_cases = 9
completed_cases = 9
agent_failed_cases = 0
review_status_counts = {reviewed: 9}
OpenCode = healthy, version 1.2.26
provider_id = deepseek
model_id = deepseek-v4-flash
```

质量审计：

```text
finding_count = 45
step2_admission_ready = false
```

主要问题：

- `empty_negative_evidence = 9`
- `non_object_source_refs = 8`
- `non_object_line_risk_signals = 8`
- `reviewed_with_uncertainty = 7`
- `cert_fixed_without_hard_certificate_candidates = 3`
- `cert_fixed_without_admission_requirements = 3`

结论：

- P1-A 证明 pipeline 可运行。
- P1-A 不证明 VET taxonomy 成熟。
- P1-A 不允许进入 Step2/Step3 admission。

### 4.2 P1-B `expanded_27`

目的：扩大到每 repo 3 个 case，覆盖更多 patch type / fix family / deterministic seed。

最终结果：

```text
planned_cases = 27
completed_cases = 27
agent_failed_cases = 0
review_status_counts = {reviewed: 27}
step2_admission_ready = false
```

覆盖：

```text
patch_type_counts = {add_only: 7, del_only: 4, mixed: 16}
fix_family_counts = {multi_commit: 10, single_commit: 17}
```

P1-B 中 8/27 个 case 的 agent-reviewed archetype 与 deterministic seed 不一致：

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

- deterministic seed 只能做候选，不能做最终 VET taxonomy。
- qemu 等复杂项目中，agent semantic refinement 是必要的。
- Step2 schema 必须支持更细粒度 archetype。

质量审计：

```text
finding_count = 38
severity_counts = {warn: 38}
step2_admission_ready = false
```

主要问题：

- `cert_fixed_with_uncertainty = 12`
- `empty_negative_evidence = 12`
- `reviewed_with_uncertainty = 12`
- `empty_line_risk_signals = 2`

相比 P1-A 的改善：

- `non_object_source_refs`: 8 -> 0
- `non_object_line_risk_signals`: 8 -> 0
- `cert_fixed_without_hard_certificate_candidates`: 3 -> 0
- `cert_fixed_without_admission_requirements`: 3 -> 0

当前问题已经从“格式不稳定”转向“证据准入语义不安全”。

## 5. P1-B Admission 初测

脚本：

```text
E:\AI\Agent\workflow\VulnVersion\tests\simulate_vet_admission_gate.py
```

命令：

```powershell
cd E:\AI\Agent\workflow\VulnVersion
python tests\simulate_vet_admission_gate.py --review-dir tests\vet_taxonomy_case_review\expanded_27 --dataset DataSet\BaseDataOrder.json --repo-root repo --out tests\vet_admission_gate_p1b --max-unaffected-per-case 30
```

口径：

- 所有 mapped GT affected tags 全量检查。
- unaffected release tags 每个 case 抽样最多 30 个。
- `wrong_cleared_affected_tags` 是精确值。
- `true_cleared_unaffected_tags` 是抽样估计。
- GT 只用于 simulator oracle。

结果：

| strategy | cleared tags | true clear | wrong affected clear | clear precision | wrong cases | 判断 |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `raw_agent_flags_any` | 891 | 521 | 370 | 0.584736 | 10 | 不能用 |
| `raw_fixed_token` | 593 | 237 | 356 | 0.399663 | 10 | 严重不安全 |
| `raw_absent_scope_or_vuln` | 349 | 335 | 14 | 0.959885 | 2 | 仍会漏报 |
| `strict_fixed_token` | 106 | 74 | 32 | 0.698113 | 3 | 加 gate 后仍不安全 |
| `strict_fixed_token_and_vuln_absent` | 0 | 0 | 0 | 0.000000 | 0 | 过严，无覆盖 |
| `strict_absent_scope_only` | 46 | 46 | 0 | 1.000000 | 0 | 当前唯一安全候选 |
| `strict_gate_any` | 152 | 120 | 32 | 0.789474 | 3 | 因 fixed 分支仍不安全 |
| `ultra_strict_gate_any` | 46 | 46 | 0 | 1.000000 | 0 | 等价于 scope-absent-only |

结论：

- raw agent certificate 不能进入 Step3。
- `CERT_FIXED` 当前禁止 hard use。
- `fix token present -> fixed` 是错误规则。
- `vulnerable token absent` 不能直接作为 absent certificate。
- `strict_absent_scope_only` 可作为实验候选，但覆盖低，不能宣称最终可用。

## 6. 已废弃或降级的思路

以下内容不再作为当前主线：

| 思路 | 当前处理 |
| --- | --- |
| 直接使用 `cert_absent_allowed / cert_fixed_allowed` | 废弃为主字段 |
| `fix token present -> NOT_AFFECTED_fixed` | 禁止 |
| `vulnerable token absent -> NOT_AFFECTED_absent` | 禁止 |
| agent 直接决定 hard certificate | 禁止 |
| P1-B 后直接跑 P1-C `full_81` | 暂停 |
| deterministic seed 作为最终 taxonomy | 禁止 |
| touched file / generic token 进入 hard certificate | 禁止 |
| 继续盲调 Step3 sentinel | 暂停，先提升 Step2 evidence quality |

## 7. Step2 v2 目标结构

Step2 v2 仍然保留 VET。VET 是总模型，不被拆掉。新的输出分成语义层和证据层：

| 层级 | 作用 | 主要消费者 |
| --- | --- | --- |
| `reviewed_vet` | 表达漏洞语义、root cause、fix semantics、guard conditions | Step3 tag judge prompt、论文解释 |
| `admission_evidence` | 明确 evidence 可进入 priority / prompt context / experimental certificate，哪些必须禁止使用 | Step3 line/tag/segment scoring、Admission gate |

推荐 schema：

```json
{
  "schema_version": "step2_vet.v2",
  "cve_id": "",
  "repo": "",
  "reviewed_vet": {
    "root_cause_summary": "",
    "vulnerability_mechanism": "",
    "fix_mechanism": "",
    "scope": {
      "files": [],
      "functions": [],
      "components": [],
      "source_refs": []
    },
    "vulnerable_condition": {
      "necessary_conditions": [],
      "vulnerable_sequences": [],
      "missing_guards": [],
      "negative_evidence": []
    },
    "fix_evidence": {
      "fix_guards": [],
      "changed_sequences": [],
      "semantic_change": ""
    },
    "guards": {
      "configuration_guards": [],
      "version_or_feature_guards": [],
      "preconditions": []
    },
    "uncertainty": []
  },
  "admission_evidence": {
    "evidence_items": [
      {
        "evidence_id": "",
        "kind": "root_cause_file | root_cause_function | vulnerable_sequence | fix_guard | semantic_invariant | grep_pattern | history_hint",
        "value": "",
        "scope": {},
        "source_refs": [],
        "local_validation": {},
        "confidence": "low | medium | high",
        "risk_flags": [],
        "agent_claimed_uses": [],
        "allowed_uses": [],
        "blocked_uses": [],
        "block_reasons": []
      }
    ]
  }
}
```

要求：

- `reviewed_vet` 是 agent 语义描述层。
- `admission_evidence` 是 Step3 打分和 prompt 的证据层。
- agent 不直接决定 final allowed uses。
- `allowed_uses / blocked_uses / block_reasons` 由 Admission gate 统一标注。

## 8. Admission gate v2 定位

Admission gate v2 不是 tag verdict，也不是 hard deletion。

它只回答：

```text
这条 evidence 可以被 Step3 怎么用？
```

输出：

```json
{
  "evidence_id": "ev_001",
  "admission_status": "accepted_priority",
  "allowed_uses": ["priority", "prompt_context"],
  "blocked_uses": ["hard_certificate"],
  "block_reasons": []
}
```

默认策略：

| evidence 类型 | 默认用途 |
| --- | --- |
| root-cause file/function | `priority`, `prompt_context` |
| vulnerable sequence | `priority`, `prompt_context` |
| fix guard | `priority`, `prompt_context` |
| semantic invariant | `prompt_context` |
| history hint | `weak_priority` |
| generic token | `blocked` 或 `prompt_context_only` |
| uncertainty evidence | `prompt_context_only` |
| source_refs 缺失 | `blocked` |
| `CERT_FIXED` | hard use 禁止 |
| `CERT_ABSENT` | 仅保留 scope-file-absent 实验候选 |

对 Step3 的影响：

- fix reachability / VersionTree 仍是 Dynamic scheduler 的硬骨架。
- VET evidence 只影响 soft priority、line/tag/segment score、representative probe selection。
- evidence 不删除 line/tag。
- evidence 不直接输出 `NOT_AFFECTED`。
- evidence 不终止 affected-positive expansion。

## 9. Step3 消费方式

Step3 后续应按以下方式使用 Step2 v2：

```text
reviewed_vet
-> tag judge prompt context

admission_evidence.evidence_items
-> Admission gate v2
-> VulnTree node/line runtime state
-> line_score / tag_score / segment_score
-> dynamic scheduler probe ordering
```

关键约束：

- Dynamic scheduler 的候选空间仍由 fix reachability + VersionTree + fallback skeleton 决定。
- VET score 只能改变候选空间内的 probe 顺序、representative tag、segment priority。
- 如果 VET score 错了，最多让 probe 顺序变差，不能让 affected line 被删除。

## 10. P2 当前执行计划

### P2-A：修改 P1 runner schema 与 prompt

目标：

- 废弃以 `cert_absent_allowed / cert_fixed_allowed` 为中心的 prompt。
- 改为输出 `reviewed_vet` 和 `admission_evidence.evidence_items`。
- 每个 evidence item 必须说明：
  - 证据是什么；
  - 为什么与 root cause 相关；
  - source_refs 是什么；
  - 是否 generic；
  - 是否适合 Step3 priority；
  - 是否适合 tag judge prompt；
  - 为什么不能作为 hard certificate。

Prompt 必须强调：

```text
Do not decide final tag verdict.
Do not claim hard certificate unless explicitly proven.
For each evidence item, state downstream use and risk.
Evidence primarily supports Step3 scoring and tag-judge prompt.
```

当前执行状态（2026-05-19）：

```text
已完成。
修改文件：E:\AI\Agent\workflow\VulnVersion\tests\run_vet_case_review_81.py
测试文件：E:\AI\Agent\workflow\VulnVersion\tests\test_vet_case_review_runner.py
```

已落实内容：

- 新增 `step2_vet.v2` 默认输出。
- 新增 `expanded_27_v2` stage，case set 与 `expanded_27` 完全一致。
- `_prompt()` 与 `_fallback_json_prompt()` 已切换到 `reviewed_vet + admission_evidence.evidence_items`。
- `_normalize_review()` 默认生成 v2 结构，并保留 deterministic case metadata。
- `audit_review_quality()` 支持 v2 evidence item 结构审计，同时保留旧 v1 兼容。
- 新增主 prompt 测试，确保真实发送给 agent 的 prompt 不再包含旧 `cert_absent_allowed / cert_fixed_allowed / hard_certificate_candidates`。
- 新增 `admission_evidence_summary.json` 输出；旧 `certificate_policy_summary.json` 仅作为兼容产物保留。

验证命令：

```powershell
cd E:\AI\Agent\workflow\VulnVersion
python -m pytest tests\test_vet_case_review_runner.py -q
python -m pytest tests\test_vet_case_review_runner.py tests\test_vet_admission_gate.py -q
python -m pytest tests -q
```

验证结果：

```text
tests\test_vet_case_review_runner.py: 11 passed
runner + admission gate tests: 15 passed
full tests: 208 passed
```

### P2-B：`expanded_27_v2` 复测

先复测同一批 27 cases，不扩大样本。

输出目录：

```text
E:\AI\Agent\workflow\VulnVersion\tests\vet_taxonomy_case_review\expanded_27_v2
```

验收指标：

| 指标 | 目标 |
| --- | --- |
| completed cases | 27/27 |
| agent_failed_cases | 0 |
| structured `evidence_items` | 100% |
| structured `source_refs` | 100% |
| empty `line_risk_signals` | 0 |
| hard certificate claim | 默认 0 |
| `allowed_uses` 或可 gate 的 usage hints | 100% |
| uncertainty 与 reviewed 混用 | 显著下降 |
| generic token 被标记 | 100% |

dry-run 已完成（2026-05-19）：

```powershell
cd E:\AI\Agent\workflow\VulnVersion
python tests\run_vet_case_review_81.py --dataset tests\vet_taxonomy_corpus\BaseDataOrder_vet_case_study_81.json --selected-cases tests\vet_taxonomy_corpus\selected_cases.json --vet-seeds tests\vet_taxonomy_corpus\vet_archetype_seed.jsonl --stage expanded_27_v2 --out tests\vet_taxonomy_case_review\expanded_27_v2 --dry-run
```

结果：

```text
planned_cases = 27
repos = 9
patch_type_counts = {add_only: 7, del_only: 4, mixed: 16}
fix_family_counts = {multi_commit: 10, single_commit: 17}
```

说明：

- dry-run 只验证 case selection 与 artifact 框架，不调用 OpenCode。
- 下一步才是真实 OpenCode `expanded_27_v2` 运行。
- 当前不得把 P2-B 视为完成。

真实 OpenCode 运行已完成（2026-05-19）：

```powershell
cd E:\AI\Agent\workflow\VulnVersion
python tests\run_vet_case_review_81.py --dataset tests\vet_taxonomy_corpus\BaseDataOrder_vet_case_study_81.json --selected-cases tests\vet_taxonomy_corpus\selected_cases.json --vet-seeds tests\vet_taxonomy_corpus\vet_archetype_seed.jsonl --stage expanded_27_v2 --out tests\vet_taxonomy_case_review\expanded_27_v2 --enable-readonly-git-tools --resume --retry-agent-failed --timeout-s 1200
```

运行结果：

```text
planned_cases = 27
completed_cases = 27
agent_failed_cases = 0
needs_manual_review_cases = 0
review_status_counts = {reviewed: 27}
OpenCode = healthy, version 1.2.26
provider_id = deepseek
model_id = deepseek-v4-flash
wall_clock ~= 77 minutes
```

质量结果：

```text
finding_count = 79
severity_counts = {error: 44, warn: 35}
step2_admission_ready = false
```

issue 分布：

```text
missing_evidence_item_field = 40
empty_negative_evidence = 22
empty_evidence_item_source_refs = 8
reviewed_vet_with_uncertainty = 5
empty_source_refs = 1
empty_necessary_conditions = 1
empty_vulnerable_condition_evidence = 1
empty_fix_evidence = 1
```

与 P1-B v1 对比：

```text
v1 finding_count = 38, severity_counts = {warn: 38}
v2 finding_count = 79, severity_counts = {error: 44, warn: 35}
v2 evidence_items_total = 176
v2 evidence_items_per_case = min 4, max 10, avg 6.52
```

对比产物：

```text
E:\AI\Agent\workflow\VulnVersion\tests\vet_taxonomy_case_review\expanded_27_v2\v1_v2_comparison.json
E:\AI\Agent\workflow\VulnVersion\tests\vet_taxonomy_case_review\expanded_27_v2\v1_v2_comparison.md
```

关键负结果：

- v2 真实运行稳定性通过：27/27 reviewed，0 agent failure。
- v2 当前 schema adherence 不合格，不能进入 Step3。
- 最大 outlier 是 `FFmpeg / CVE-2020-22019`：agent 输出了 7 个 evidence item，但 `reviewed_vet` 基本为空，且 evidence item 缺少 `scope / source_refs / local_validation / risk_flags / blocked_uses / block_reasons` 等字段。
- 因此当前瓶颈不是 OpenCode 后端稳定性，而是 v2 prompt 对 `reviewed_vet` 和 `evidence_items` 的强制性不足。

当前结论：

- P2-B “真实运行”已完成。
- P2-B “验收通过”未完成。
- 暂停 P2-C simulator，先修 v2 prompt/schema adherence，并增加 quality-failed case 的定向重跑机制。

#### P2-B 定向重跑修复结果（2026-05-21）

本轮修改：

- 强化 v2 prompt，明确要求：
  - 不允许 `reviewed_vet` 为空；
  - 不允许遗漏 evidence item 字段；
  - 每个 evidence item 必须包含结构化 `source_refs`；
  - `local_validation` 必须说明 tag-level 检查方式或解释为什么只能作为 context。
- 新增 `--retry-quality-failed`：
  - 读取当前输出目录的 `quality_findings.json`；
  - 默认只重跑 `severity == error` 的 CVE；
  - warning 不触发重跑，避免退化成 27 cases 全量重跑。

验证命令：

```powershell
cd E:\AI\Agent\workflow\VulnVersion
python -m pytest tests\test_vet_case_review_runner.py -q
python -m pytest tests\test_vet_case_review_runner.py tests\test_vet_admission_gate.py -q
python -m pytest tests -q
```

验证结果：

```text
tests\test_vet_case_review_runner.py: 13 passed
runner + admission gate tests: 17 passed
full tests: 210 passed
```

由于原 `expanded_27_v2` 目录当前在 Windows 环境下不可写，本轮定向重跑写入新的可写目录：

```text
E:\AI\Agent\workflow\VulnVersion\tests\vet_retry_expanded_27_v2_quality
```

定向重跑命令：

```powershell
cd E:\AI\Agent\workflow\VulnVersion
python tests\run_vet_case_review_81.py --dataset tests\vet_taxonomy_corpus\BaseDataOrder_vet_case_study_81.json --selected-cases tests\vet_taxonomy_corpus\selected_cases.json --vet-seeds tests\vet_taxonomy_corpus\vet_archetype_seed.jsonl --stage expanded_27_v2 --out tests\vet_retry_expanded_27_v2_quality --enable-readonly-git-tools --resume --retry-agent-failed --retry-quality-failed --timeout-s 1200
```

定向重跑结果：

```text
planned_cases = 27
completed_cases = 27
agent_failed_cases = 0
quality_retry_requested = true
quality_retry_case_count = 1
quality_retry_case_ids = [CVE-2020-22019]
retry_latency_CVE_2020_22019 = 68.266s
```

质量改善：

```text
before retry:
  finding_count = 79
  severity_counts = {error: 44, warn: 35}

after retry:
  finding_count = 28
  severity_counts = {warn: 28}
```

剩余问题：

```text
empty_negative_evidence = 22
reviewed_vet_with_uncertainty = 5
empty_evidence_item_source_refs = 1
```

当前判断：

- v2 prompt/schema adherence 的结构性错误已显著下降。
- `missing_evidence_item_field` 从 40 降到 0。
- `empty_source_refs / empty_necessary_conditions / empty_vulnerable_condition_evidence / empty_fix_evidence` 均降到 0。
- 剩余问题主要是 evidence completeness，而不是 JSON/schema adherence。
- P2-C simulator 可以准备，但在进入 Step3 主流程前，必须继续跟踪 `empty_negative_evidence` 和 `reviewed_vet_with_uncertainty` 对 tag judge / line scoring 的影响。

### P2-C：Admission gate v2 simulator

P1-B v2 后，不再只测试 wrong hard certificate，还要测试 evidence profile 是否能降低 Step3 probe。

建议脚本：

```text
E:\AI\Agent\workflow\VulnVersion\tests\simulate_vet_evidence_profile_segmentation.py
```

测试链路：

```text
Step2 v2 evidence_items
-> Admission gate v2
-> tag evidence profile
-> homogeneous evidence segment
-> segment endpoint / sentinel probe
-> GT oracle evaluation
```

必须统计：

| 指标 | 目的 |
| --- | --- |
| avg probes/CVE | 是否降本 |
| segment count/CVE | 分段是否过碎 |
| wrong segment inference | 是否误扩展 |
| version FN | 是否漏报 |
| exact CVE | 是否影响 CVE 级准确率 |
| profile conflict cases | 找出 evidence 不够强的地方 |
| line_score / tag_score coverage | 看 evidence 是否真的服务 Step3 |

### P2-D：进入 `full_81` 的条件

只有满足以下条件，才运行 P1-C `full_81`：

1. `expanded_27_v2` 完成 27/27。
2. Step2 v2 schema reload 100%。
3. evidence items 结构化率 100%。
4. Admission gate v2 不再产生危险 hard semantics。
5. Evidence profile segmentation 在 27 cases 上有可见收益，且 version FN 不显著增加。

P1-C 的目标改为：

```text
扩大 VET archetype + evidence_items + allowed_uses 覆盖，
不是收集更多 certificate。
```

## 11. 当前风险清单

| 风险点 | 当前状态 | 后续动作 |
| --- | --- | --- |
| 错误 `CERT_ABSENT` | 只允许 scope-file-absent 候选继续测试 | expanded_27_v2 后扩大验证 |
| 错误 `CERT_FIXED` | 当前禁止 hard use | 设计 root-cause sequence + fix guard 局部绑定 gate |
| `negative_evidence` 缺失 | admission blocker | prompt v2 强制填充或解释不可用 |
| `source_refs` 不完整 | 只能 priority-only 或 blocked | schema v2 强制结构化 |
| large patch context 不全 | 会导致 root cause 抽象偏移 | Step1 packet + read-only git tools |
| multi-commit 语义混杂 | 容易污染 VET | 默认 OR evidence bundle，复杂情况 risk flag |
| taxonomy 过细但无 admission | archetype 不等于可用证据 | evidence_items + allowed_uses 分离 |
| `line_risk_signals` 为空 | Step3 无法打分 | schema v2 中将其转为 evidence_items |

## 12. 立即执行顺序

1. 已完成：修改 `tests\run_vet_case_review_81.py`，新增 Step2 v2 schema 输出。
2. 已完成：修改 P1 prompt，使 agent 输出 `reviewed_vet` 与 `admission_evidence.evidence_items`。
3. 已完成：新增 schema v2 测试，保证 reload 和 required fields。
4. 已完成：生成 `expanded_27_v2` dry-run，确认 case set 与 P1-B 一致。
5. 已完成但未验收通过：真实 OpenCode 跑 `expanded_27_v2`。
6. 已完成：对比 P1-B v1 vs v2。
7. 已完成：修 v2 prompt/schema adherence，解决 `reviewed_vet` 为空与 evidence item 缺字段问题。
8. 已完成：实现 quality-failed case 的定向重跑机制，避免 27 cases 全量重复跑。
9. 待执行：写 `simulate_vet_evidence_profile_segmentation.py`。
10. 待执行：如果 27 cases 证明有收益，再跑 `full_81`。
11. 待执行：最后才考虑 Step3 主流程接入。

## 13. 文档维护规则

- 本文档只保留当前有效路线、实测结论、负结果和执行门槛。
- 已被实验证伪的路线应保留为简短负结果，不再保留长篇历史过程。
- 新增方案必须包含路径、命令、指标和是否进入主线的判断。
- 如果实验失败，必须记录失败原因，不能删除失败记录。
