# VulnVersion Step2 设计文档：Root-Cause-Level VET Extraction

更新时间：2026-05-13

本文档是 VulnVersion Step2 的重新设计文档。目标不是复述当前源码，而是定义下一版 Step2 应该如何服务 Step3，使 Step3 的 tag-level agent judge 能达到高精度、低成本、可解释、可验证。

当前 Step3 的瓶颈已经明确：tag plan 的无关 line 激活过多，而动态 scheduler 依赖的 cheap evidence 质量不足。Step2 因此必须从“生成一份普通 RCI JSON”升级为“生成 root-cause-level Vulnerability Existence Theorem（VET）和可验证 evidence graph”。

## 1. Step2 的职责边界

Step2 的核心职责：

> 给定 CVE、repo、fix commit family、CVE 描述和 Stage1 patch chunks，抽取一个可以跨 release tags 验证的 root-cause-level VET。

Step2 不负责：

- 不决定最终 affected versions。
- 不决定 Step3 扫描哪些 tags。
- 不读取 ground truth affected versions。
- 不根据数据集答案反推规则。
- 不把 weak evidence 伪装成 hard certificate。
- 不直接输出 `AFFECTED / NOT_AFFECTED` tag verdict。

Step2 必须负责：

- 抽取漏洞根因相关文件、函数、语句序列、guard、约束条件。
- 区分 root-cause evidence 与普通 touched evidence。
- 为 Step3 提供 line/tag priority evidence。
- 为 Step3 agent prompt 提供压缩后的漏洞存在性判别上下文。
- 标注每条 evidence 的来源、强度、允许用途和风险。
- 输出可被 simulator 验证的结构化 artifact。

## 2. Step2 与 Step3 的关系

Step3 当前主线：

```text
release tags
-> release filter / version normalization
-> repo-aware VersionTree / line-family graph
-> fix reachability evidence
-> active-line scheduler
-> ASBS / sentinel probes
-> agent tag verdict
-> interval inference
-> affected versions
```

Step2 应该插入的位置：

```text
Stage1 patch chunks
-> Step2 root-cause-level VET
-> Step3 VET Evidence Graph
-> line/tag risk score
-> active-line scheduler priority
-> compact tag judge prompt
```

关键约束：

- Step2 evidence 默认只能影响 priority、activation order、prompt context。
- 只有通过 1128 CVE simulator admission 的 evidence，才允许成为 `CERT_ABSENT` / `CERT_FIXED`。
- Step3 agent 的输入应该是压缩后的 VET，不应该是大量无关上下文。

## 3. Step2 输入规范

### 3.1 必需输入

| 输入 | 来源 | 用途 |
| --- | --- | --- |
| `cve_id` | dataset | 标识漏洞 |
| `repo` | dataset | 目标项目 |
| `repo_path` | local repo | git 查询 |
| `fixing_commits` | dataset | fix commit family |
| `primary_fix_commit` | dataset / normalized | 默认主修复 commit |
| `cve_description` | dataset / NVD / advisory | 漏洞语义 |
| `cwe` | dataset | 漏洞类型先验 |
| `patch_semantics.json` | Stage1 | chunk、diff、chunk role |

### 3.2 Stage1 输入要求

Stage1 输出至少应包含：

| 字段 | 要求 |
| --- | --- |
| `all_chunks` | 每个 fix commit 的 diff chunks |
| `chunk_roles` | `PRIMARY_FIX / SUPPORTING_FIX / CONTEXTUAL_CHANGE / UNRELATED` |
| `rci_relevant_chunks` | Step2 优先分析的 chunks |
| `excluded_chunks` | 排除原因 |
| `fix_commits` | 去重后的 fix family |

Step2 不应只信任 Stage1 的 role。Stage2 必须自己基于 diff 做 deterministic extraction，再用 agent 做语义精炼。

### 3.3 禁止输入

Step2 禁止读取：

- GT affected versions。
- Step3 tag plan。
- Step3 probe 结果。
- final eval。
- 任何从 ground truth 反推出的 CVE-specific rule。

## 4. Step2 输出规范

Step2 的核心输出建议为：

```text
root_cause_vet.json
vet_evidence_graph.json
vet_admission_input.json
rci.json
step2_self_check.json
```

### 4.1 `root_cause_vet.json`

这是 Step2 最重要的输出。

```json
{
  "schema_version": "root_cause_vet.v1",
  "cve_id": "",
  "repo": "",
  "fix_commits": [],
  "root_cause_summary": "",
  "vulnerability_mechanism": "",
  "security_invariant": "",
  "root_cause_files": [],
  "root_cause_functions": [],
  "vulnerable_sequences": [],
  "fix_guards": [],
  "feature_introduction_clues": [],
  "component_scope": [],
  "negative_applicability_conditions": [],
  "grep_patterns": [],
  "git_log_sg_queries": [],
  "certificate_candidates": [],
  "confidence": {},
  "risk_flags": []
}
```

### 4.2 `vet_evidence_graph.json`

这是给 Step3 scheduler 使用的 evidence graph。

```text
VET nodes:
  CVE
  fix_commit
  root_cause_file
  root_cause_function
  vulnerable_sequence
  fix_guard
  grep_pattern
  git_log_query
  release_line
  release_tag

VET edges:
  fix_commit -> modifies -> file/function
  vulnerable_sequence -> located_in -> file/function
  fix_guard -> guards -> vulnerable_sequence
  release_tag -> contains_file/function/token/guard
  release_line -> has_evidence_score -> score
```

该图只提供 priority 和解释，不直接删除 line/tag。

### 4.3 `vet_admission_input.json`

用于后续 `simulate_vet_quality_admission.py`。

必须包含：

- 每个 evidence 的 `pattern_id`
- `kind`
- `value`
- `scope_files`
- `strength`
- `allowed_uses`
- `source_refs`
- `expected_check`
- `risk_flags`

### 4.4 `rci.json`

`rci.json` 可以保留为兼容输出，但下一版不应作为唯一 Step2 产物。它应该从 `root_cause_vet.json` 派生，而不是反过来。

## 5. VET 核心形式

下一版 Step2 的 VET 不应再只是传统：

```text
Θ = <A, Pvuln, Pfix, G>
```

它应拆成两层：

```text
Θ = <S, V, F, G, C>
```

其中：

| 符号 | 含义 |
| --- | --- |
| `S` | Scope：漏洞适用范围，包括 file/function/component/feature |
| `V` | Vulnerable Evidence：漏洞存在所需的关键代码序列或语义条件 |
| `F` | Fix Evidence：修复后应出现的 guard/check/API/semantic change |
| `G` | Guard Conditions：排除误判的上下文约束 |
| `C` | Certificate Policy：哪些 evidence 可用于 priority，哪些可作为 certificate candidate |

### 5.1 Scope `S`

Scope 不是 touched files。

Scope 应回答：

- 漏洞发生在哪个组件？
- 哪些文件/函数是 root cause？
- 哪些文件只是测试、文档、重构、wrapper？
- 是否存在 feature flag、build option、platform condition？

### 5.2 Vulnerable Evidence `V`

Vulnerable evidence 应优先是局部代码序列，而不是普通 token。

例子：

```text
read attacker-controlled length
allocate buffer based on smaller bound
copy using attacker-controlled length
missing bound check
```

可编码为：

- ordered token sequence
- AST-like statement sequence
- function-local data-flow clue
- vulnerable API misuse pattern
- missing guard condition

### 5.3 Fix Evidence `F`

Fix evidence 应描述 patch 如何破坏漏洞条件。

例子：

- added bound check
- added NULL check
- added length normalization
- replaced unsafe API
- added state validation
- disabled unsafe path
- changed parser state machine

### 5.4 Guards `G`

Guards 用于减少跨版本误判。

包括：

- file rename / function rename
- alternative implementation
- feature not present
- platform-specific path
- test-only code
- backport-specific rewrite
- multi-commit partial fix

### 5.5 Certificate Policy `C`

默认策略：

```text
all evidence = priority_only
```

只有满足以下条件才可能成为 certificate candidate：

- evidence 局部、强、可复现。
- 在 vuln/fix commit 上自检通过。
- 在 1128 CVE simulator admission 中 wrong-certificate case 足够低。
- 能解释为什么不会漏 affected tag。

## 6. Evidence 强度与允许用途

每条 evidence 必须有：

```json
{
  "pattern_id": "",
  "kind": "",
  "value": "",
  "scope_files": [],
  "strength": "weak|medium|strong",
  "allowed_uses": ["priority", "prompt_context"],
  "evidence": [],
  "risk_flags": []
}
```

### 6.1 `weak`

只能用于 priority 或 prompt context。

常见 weak evidence：

- 普通 touched file。
- generic token。
- commit message token。
- repo-wide API name。
- CWE generic word。

### 6.2 `medium`

可以用于 priority 排序，但不能单独作为 certificate。

常见 medium evidence：

- root-cause file with localized hunk。
- function name validated at vuln/fix commit。
- patch-adjacent token sequence。
- component-specific API。

### 6.3 `strong`

可以进入 certificate candidate，但仍需 admission。

常见 strong evidence：

- function-local vulnerable statement sequence。
- patch-introduced guard with exact local context。
- data-flow relevant condition。
- validated rename-aware root-cause file/function。

## 7. Step2 生成流程

下一版 Step2 应分为 deterministic layer 和 agent refinement layer。

```text
Input
-> deterministic diff extractor
-> root-cause candidate builder
-> git validation layer
-> agent semantic refinement
-> schema validator
-> self-check
-> admission artifact
```

### 7.1 deterministic diff extractor

先由程序稳定抽取：

- changed files
- hunks
- added lines
- deleted lines
- modified functions
- surrounding context
- simple rename candidates
- added guards/checks/API calls
- removed vulnerable expressions
- changed constants / bounds / state transitions

这一步不能依赖 agent。

### 7.2 root-cause candidate builder

把 diff 信息转成候选 evidence：

| candidate | 来源 |
| --- | --- |
| root-cause files | PRIMARY/SUPPORTING chunks + function context |
| root-cause functions | hunk header + lightweight parser + grep fallback |
| vulnerable sequences | removed lines + pre-fix surrounding context |
| fix guards | added if/check/return/error/API lines |
| grep patterns | short non-generic code fragments |
| git log queries | deleted/added critical tokens for `-S/-G` |
| component scope | path prefix + file role |

### 7.3 git validation layer

对候选 evidence 在 `fix_commit` 和 `fix_commit^` 上做检查：

| 检查 | 目的 |
| --- | --- |
| `git show fix^:path` | vuln-side file 是否存在 |
| `git show fix:path` | fix-side file 是否存在 |
| `git grep token fix^` | vulnerable token 是否存在 |
| `git grep token fix` | fix token 是否存在 |
| function context extraction | token 是否在正确函数附近 |
| sequence order check | ordered sequence 是否局部成立 |
| rename search | 跨版本路径稳定性 |

这一步输出 validation score，不输出 tag verdict。

### 7.4 agent semantic refinement

agent 只做语义判断，不做全量自由生成。

输入给 agent：

- CVE description
- deterministic candidates
- pre/fix local snippets
- validation result
- Stage1 chunk roles

agent 输出：

- 哪些 candidate 是 root cause。
- 哪些只是 incidental。
- 漏洞机制。
- fix mechanism。
- 哪些 evidence 是 weak/medium/strong。
- 哪些 evidence 只能 priority。
- 哪些可作为 certificate candidate。
- risk flags。

### 7.5 schema validation

任何 agent 输出必须过 schema。

不合格时：

- 不能静默使用。
- 降级为 deterministic evidence。
- 在 artifact 标记 `agent_refinement_failed`。

## 8. Step3 使用方式

Step3 使用 Step2 输出分三层。

### 8.1 Prompt Context

给 tag judge agent：

```text
This tag is affected iff:
  scope exists
  vulnerable sequence exists
  fix guard absent or insufficient
  guards do not exclude this version
```

tag judge 只输出：

```text
AFFECTED / NOT_AFFECTED
```

不得输出：

- uncertain
- need more evidence
- maybe
- partial

### 8.2 Priority Evidence

给 scheduler：

- line score
- tag score
- scout priority
- neighbor activation priority
- conflict priority

不能直接 hard delete。

### 8.3 Certificate Candidate

只有 admission 通过后才允许：

- `CERT_ABSENT`
- `CERT_FIXED`

在 admission 前，全部 certificate candidate 只作为实验字段。

## 9. Step2 质量评估

Step2 不能只看“agent 输出看起来合理”。必须有实验 gate。

### 9.1 commit-local self-check

检查：

- root-cause file exists at `fix^`
- root-cause file exists at `fix`
- vulnerable sequence holds at `fix^`
- fix guard holds at `fix`
- fix guard absent at `fix^`

### 9.2 release-tag evidence coverage

在 release tags 上统计：

- root-cause file coverage
- function coverage
- vulnerable sequence hit rate
- fix guard hit rate
- evidence conflict rate
- evidence missing rate

### 9.3 scheduler simulator admission

必须使用：

```text
E:\AI\Agent\workflow\VulnVersion\DataSet\BaseDataOrder.json
```

评估：

- evidence-ranked scheduler 是否减少 probe。
- version FN 是否增加。
- wrong certificate count。
- skipped affected line count。
- per-repo failure cases。

### 9.4 tag judge accuracy admission

目标：

> Step3 selected tag judge accuracy 必须高于 99%。

评估方式：

- 从 9 repo 抽样 selected probes。
- 覆盖 affected / not affected。
- 覆盖 high-probe repo。
- 覆盖 sparse/singleton affected tags。
- 覆盖 multi-commit CVE。
- 记录 actual agent latency 和 error。

## 10. Multi-commit CVE 处理

Step2 不需要复杂恢复 line-local FIC。

但 Step2 必须处理 multi-fix evidence bundle。

默认策略：

```text
multi fix commits = OR evidence bundle
```

即：

- 每个 fix commit 独立抽取 diff evidence。
- 合并 root-cause candidates。
- 去重相同 file/function/sequence/guard。
- 不轻易声明 AND/composite。

只有在 deterministic diff 显示多个 commit 修改同一 root-cause path 且每个 commit 只完成部分 guard 时，才标记：

```text
possible_composite_fix
```

该标记只作为 risk flag，不改变 Step3 默认规划。

## 11. 关键 artifact

Step2 应输出以下文件：

| artifact | 作用 |
| --- | --- |
| `deterministic_diff_evidence.json` | 程序抽取的原始 evidence |
| `root_cause_candidates.json` | 未经 agent 精炼的候选 |
| `root_cause_vet.json` | 最终 VET |
| `vet_evidence_graph.json` | 给 Step3 scheduler 的 evidence graph |
| `vet_admission_input.json` | 给 simulator 的 admission 输入 |
| `rci.json` | 兼容旧流程 |
| `step2_self_check.json` | commit-local 自检 |
| `step2_agent_trace.jsonl` | agent 精炼过程 |
| `step2_quality_report.json` | 质量汇总 |

## 12. 失败与降级策略

| 失败情况 | 降级策略 |
| --- | --- |
| agent 输出 JSON 失败 | 使用 deterministic evidence，标记 `agent_refinement_failed` |
| root-cause function 找不到 | 降级到 file-level scope，strength 降为 weak/medium |
| vulnerable sequence 太 generic | 只允许 prompt_context，不允许 priority 或 certificate |
| fix guard 不稳定 | 只作为 prompt_context |
| rename 不确定 | 添加 risk flag，不做 absent certificate |
| multi-commit 无法分类 | OR evidence bundle + risk flag |

## 13. Step2 必须面对的坑与防护设计

本节记录 Step2 设计中必须主动处理的反例。来源包括：How-far-are-we baseline 中 tracing-based / matching-based 方法的经验、相关工作中关于 patch / SZZ / version-tree 的讨论、以及当前 VulnVersion 在 1128 CVE 上的 Step3 simulator 负结果。

核心原则：

> Step2 不能假设 patch commit 等于 root cause，也不能假设 patch token 等于 vulnerability token。Step2 必须把“证据候选”“语义判断”“可跨版本验证能力”分开建模。

### 13.1 Patch commit 不一定包含 root cause

问题：

- 有些 patch commit 只是加 guard、加配置、换 API、禁用路径，真正 root cause 在更早的设计或代码中。
- 有些 patch 是 workaround，不直接暴露漏洞形成机制。
- 有些 patch 只修复 crash surface，不修复根因。
- 有些 patch 是大重构的一部分，root cause 被淹没在大量 unrelated changes 中。

风险：

- 如果 Step2 只从 added lines 抽 fix token，会得到 `CERT_FIXED` 假象。
- 如果 Step2 只从 removed lines 抽 vuln token，可能完全找不到 vulnerable sequence。
- Step3 agent 会被引向“patch 存在/不存在”，而不是“漏洞是否存在”。

防护设计：

- Step2 必须输出 `fix_mechanism` 和 `vulnerability_mechanism` 两个不同字段。
- `fix_guard` 不能自动等价于 `root_cause`。
- 对每个 evidence 增加 `evidence_role`：
  - `root_cause`
  - `fix_guard`
  - `symptom`
  - `workaround`
  - `refactor_noise`
  - `test_or_doc`
- 如果只能证明 patch 行为，不能证明 root cause，则标记：
  - `risk_flags: ["patch_not_root_cause"]`
  - `certificate_allowed: false`

### 13.2 Fix commit 可能是纯添加代码

问题：

- 很多漏洞修复是添加 guard/check，没有 deleted vulnerable line。
- 此时 vulnerable code 不是“被删除的代码”，而是“缺少某个约束的旧代码路径”。

风险：

- matching-based 方法容易只看 added guard，无法表示“guard absent”才是 vulnerable 条件。
- `vulnerable_sequence_exists` 可能在 fix 前后都存在，导致误判。

防护设计：

- Step2 必须支持 `missing_guard_condition` 类型。
- `V` 不应只表示“存在某段代码”，还应表示“在某段代码附近缺失某个 guard”。
- VET 中应编码：

```text
scope exists
AND vulnerable operation exists
AND fix guard absent or insufficient
```

而不是：

```text
vulnerable token exists
```

### 13.3 Fix commit 可能删除功能或禁用路径

问题：

- 有些修复通过删除功能、禁用协议、移除 parser 分支完成。
- 这类 patch 的 fix evidence 是 feature absence，而不是 guard presence。

风险：

- `file/function absent` 可能表示“不受影响”，也可能表示“代码被重构/改名后仍受影响”。
- 不能直接把 absent 当作 `NOT_AFFECTED_absent`。

防护设计：

- `negative_applicability_conditions` 必须区分：
  - `feature_absent`
  - `file_renamed`
  - `implementation_moved`
  - `component_disabled`
- `CERT_ABSENT` 必须满足 rename-aware / move-aware 检查。
- 如果只是路径不存在，默认只能作为 weak evidence。

### 13.4 Multi-commit CVE 不是天然 AND

问题：

- 多 commit CVE 可能是 backport bundle。
- 可能是一个真实修复加 merge/wrapper/changelog。
- 可能是多个不同组件分别修同一 CVE。
- 少量情况才是真 composite fix。

风险：

- 把所有 commits 当 AND 会漏掉 line-local backport。
- 把所有 commits 当 OR 会把 unrelated/wrapper commit 的 tokens 引入 VET。

防护设计：

- 默认 `multi_fix_semantics = OR evidence bundle`。
- Step2 对每个 commit 独立抽取 evidence，再做 cluster：
  - `same_patch_backport`
  - `component_parallel_fix`
  - `wrapper_or_merge_noise`
  - `possible_composite_fix`
- `possible_composite_fix` 只作为 risk flag，不能改变 Step3 默认规划。
- 对 wrapper/merge/changelog commit，默认不生成 root-cause evidence。

### 13.5 Patch 中存在大量非安全变更

问题：

- 大 patch 中可能混有格式化、重构、测试、文档、性能优化。
- Stage1 chunk role 可能判断错。

风险：

- Step2 把 incidental token 当成 root-cause token。
- Step3 evidence score 被无关文件污染，激活无关 line。

防护设计：

- deterministic extractor 必须先标记 file role：
  - `source`
  - `test`
  - `doc`
  - `build`
  - `generated`
  - `format_only`
- agent refinement 只能在 candidate 上选择，不能自由添加大量新文件。
- 普通 touched files 默认 `strength=weak`。
- 只有出现在 PRIMARY/SUPPORTING chunk 且处于漏洞机制附近的文件/函数，才能升到 medium/strong。

### 13.6 Root-cause function 可能跨版本改名、移动、拆分

问题：

- release tags 中 file/function 可能被 rename、split、merge。
- 旧版本的 vulnerable code 可能在旧路径。

风险：

- anchor 在 fix commit 成立，但在旧 tag 不成立。
- Step3 agent 找不到 anchor，误判 NOT_AFFECTED。

防护设计：

- Step2 必须输出 `rename_candidates` 和 `alternative_scope_patterns`。
- `root_cause_files` 应包含：
  - `current_path`
  - `vuln_side_path`
  - `historical_path_candidates`
  - `path_confidence`
- 对 function 应输出：
  - `current_name`
  - `historical_name_candidates`
  - `signature_tokens`
  - `body_tokens`
- anchor absent 只能触发 `needs_fallback_search`，不能直接触发 hard NOT_AFFECTED，除非 admission 证明安全。

### 13.7 Vulnerable token 可能太 generic

问题：

- token 如 `memcpy`、`length`、`size`、`return -1`、`NULL` 在项目中大量存在。
- matching-based baseline 的经验说明 token/hash 匹配可能高精度但语义覆盖不足，泛化到 refactor 后容易漏或误报。

风险：

- generic token 会让 evidence score 虚高。
- agent prompt 被无关 token 干扰。

防护设计：

- Step2 必须计算 `token_specificity`：
  - repo-wide hit count
  - file-local hit count
  - function-local hit count
  - across-release stability
- 高泛化 token 只能 `prompt_context`，不能 `priority`，更不能 certificate。
- strong vulnerable sequence 应是 ordered/localized sequence，而不是单 token。

### 13.8 Fix guard 可能不是充分修复条件

问题：

- 某个 guard 存在不代表漏洞完全修复。
- 后续版本可能又改动 guard。
- backport 可能使用不同 guard 形式。

风险：

- `fix_guard_exists -> NOT_AFFECTED` 会漏报。
- fixed segment clear 如果只看 guard，会不安全。

防护设计：

- `fix_guard` 必须绑定 vulnerable operation 和 local scope。
- Step2 应输出 `guard_semantics`：
  - bounds check
  - null check
  - type/state validation
  - permission check
  - parser state transition
- `CERT_FIXED` 需要同时满足：
  - fix guard present
  - vulnerable condition neutralized
  - local scope matches
  - admission simulator wrong cases 低

### 13.9 Root cause 可能是数据流/状态机，而不是局部 token

问题：

- 漏洞可能依赖 attacker-controlled data flow、state transition、lifetime、locking、race、permission context。
- 单纯 grep/token 无法表达。

风险：

- VET 过度简化，tag judge 准确率上不去。

防护设计：

- VET 支持 `semantic_invariant`：
  - source
  - sink
  - missing validation
  - state precondition
  - privilege condition
- Step2 agent 应负责把 deterministic candidates 总结成 semantic invariant。
- 对不能低成本检查的 invariant，标记为 `agent_only_context`，不要进入 scheduler hard gate。

### 13.10 Component / feature 不存在不等于安全

问题：

- 某 release line 可能没有某文件，但有同等功能的旧实现。
- 某组件可能以不同名字存在。

风险：

- `file_absent -> NOT_AFFECTED` 漏报。

防护设计：

- `CERT_ABSENT` 需要 feature-level absence，不是 path-level absence。
- 需要 `component_scope` 与 `feature_introduction_clues`。
- 如果只知道 file absent，则最多降低 priority。

### 13.11 Developer log / issue / commit message 可能有用但不可靠

问题：

- TDSC 类工作强调 patch 和 developer logs 可提供 affected-version 线索。
- 但 commit message 可能不完整、误导、只描述 symptom。

风险：

- 直接把 log 文字变成 VET 证据会引入 hallucinated semantics。

防护设计：

- logs 只能作为 `evidence_ref` 或 `git_log_sg_query`。
- log-derived evidence 默认 weak/medium。
- 必须被 code evidence 支撑后才能提升强度。

### 13.12 SZZ / VIC 信息有启发，但不能作为 Step2 主依赖

问题：

- SZZ/AgentSZZ/Beyond Blame 的核心是寻找 bug-introducing commit。
- VulnVersion 的目标是 affected release versions。
- 当前数据和实验表明 line-local FIC/VIC recovery 不适合作为主线。

可迁移思想：

- git blame / git log / file history 可帮助定位 root-cause code history。
- graph search 可帮助围绕 file/function/token 搜索相关上下文。
- agent 可以作为语义侦探，但不应决定 tag plan。

防护设计：

- Step2 可以使用 git blame/log 生成 root-cause候选和 history clues。
- 不把 VIC recovery 作为必要条件。
- 不把 SZZ 输出直接转成 affected version 边界。

### 13.13 Matching-based 方法可借鉴，但不能直接照搬

问题：

- ReDeBug/VUDDY/MOVERY/V1SCAN/FIRE/VULTURE 等 matching-based 方法通常依赖 token、hash、function、slice、taint 或 recurring pattern。
- 它们适合 cheap evidence 和 candidate ranking，但容易受 refactor、semantic equivalent patch、feature absence 影响。

防护设计：

- Step2 可以生成 greppable patterns、function patterns、vulnerable sequence patterns。
- 这些模式先用于 priority/ranking。
- 只有经过 admission 的 pattern 才能进入 certificate candidate。

### 13.14 Agent 可能编造或过度确信

问题：

- agent 可能生成不存在的函数、错误路径、不真实的 invariant。
- agent 可能把 CVE 描述中的高层信息强行映射到错误代码。

风险：

- Step3 tag judge 被错误 VET 系统性带偏。

防护设计：

- agent 不允许自由生成 evidence；只能 refine deterministic candidates。
- 每条 agent 结论必须引用本地 `git_show/git_grep/git_diff` evidence。
- schema 中必须区分：
  - `agent_asserted`
  - `git_validated`
  - `dataset_admitted`
- 未 git validated 的 evidence 不得进入 priority。

### 13.15 Commit-local self-check 不等于跨版本可靠

问题：

- 在 `fix^` / `fix` 上通过，不代表在 release tags 上稳定。
- 这正是 Step3 低成本调度失败的根源之一。

防护设计：

- Step2 必须输出 `vet_admission_input.json`。
- 必须跑 release-tag coverage：
  - pattern coverage
  - wrong certificate
  - skipped affected line
  - per-repo failure cases
- admission 前，所有 evidence 只能作为 priority/prompt context。

### 13.16 Step2 不能过拟合 1128 CVE

问题：

- 当前目标数据集是 How-far-are-we 的 1128 CVE / 9 repo。
- 方法设计必须服务该数据集，但不能写成 case-specific if-else。

防护设计：

- repo-aware 可以接受，因为 repo tag/version/branch convention 客观存在。
- CVE-specific GT-driven rule 不允许。
- 所有策略必须报告：
  - 训练/调参用 simulator 结果
  - failure cases
  - 被否定策略
  - 是否只是 hypothesis

### 13.17 Step2 必须输出“不能确定”的风险，而不是伪装确定

问题：

- 有些 CVE 的 root cause 就无法从 patch 充分恢复。
- 有些 evidence 只能支持 agent prompt，不能支持 scheduler。

防护设计：

- VET 必须允许：
  - `risk_flags`
  - `uncertain_scope`
  - `weak_root_cause`
  - `agent_only_context`
  - `no_certificate_allowed`
- 这不是失败，而是防止 Step3 漏报的必要信息。

## 14. 需要重点实测的问题

下一轮 Step2 设计必须把以下问题转化为脚本和指标。

### 14.1 当前补丁类型分布

当前数据集补丁类型统计：

| patch type | count |
| --- | ---: |
| Add-only | 329 |
| Del-only | 20 |
| Mixed | 1193 |

解释：

- `Add-only` 数量很高，说明大量 CVE 修复是新增 guard/check/API/validation，而不是删除 vulnerable code。
- 因此 Step2 不能只依赖 deleted lines 恢复 root cause。
- 对 `Add-only` patch，VET 必须重点表达 `missing_guard_condition`：旧版本受影响不是因为某个“漏洞 token 存在”，而是因为关键操作附近缺少新增 guard。
- `Mixed` 仍是最大类，说明 Step2 需要同时建模 vulnerable sequence 与 fix guard。
- `Del-only` 数量较少，但需要特别处理 feature removal / unsafe path removal，不能简单把文件或函数 absent 当作安全。

| 问题 | 测试方式 | 关键指标 |
| --- | --- | --- |
| patch 是否足够恢复 root cause | 对 1128 CVE 抽取 deterministic candidates | root-cause coverage、agent refinement success |
| touched file 是否误导 scheduler | line relevance simulator | skipped affected line、irrelevant active line |
| vulnerable sequence 是否稳定 | release-tag grep/sequence check | hit rate、wrong absence |
| fix guard 是否可判 fixed | fix-side coverage + GT simulator | wrong `CERT_FIXED` |
| file/function absent 是否可判 absent | rename-aware release scan | wrong `CERT_ABSENT` |
| generic token 风险 | repo-wide/token frequency | false high-score lines |
| multi-commit OR bundle 是否足够 | 68/69 multi-commit cases专项 | FN/FP、missed component |
| agent refinement 是否可靠 | 18+ CVE OpenCode sample | tag judge accuracy、latency、parse error |

## 15. 下一步开发顺序

### P0：定义 schema 和 deterministic extractor

新增或重构：

```text
vulnversion/stage2_rci_navigation/vet_schema.py
vulnversion/stage2_rci_navigation/diff_extractor.py
vulnversion/stage2_rci_navigation/root_cause_candidates.py
```

目标：

- 不依赖 agent，也能输出候选 evidence。
- 覆盖 1128 CVE。
- artifact 可复现。

### P1：agent semantic refinement

新增：

```text
vulnversion/stage2_rci_navigation/refine_vet.py
```

目标：

- agent 只判断 deterministic candidates。
- 不让 agent 自由发明 evidence。
- 输出严格 schema。

### P2：VET quality admission simulator

新增：

```text
E:\AI\Agent\workflow\VulnVersion\tests\simulate_vet_quality_admission.py
```

目标：

- 判断 VET evidence 是否可以进入 Step3 scheduler。
- 不通过 admission 的 evidence 不允许 hard certificate。

### P3：真实 OpenCode 小样本

在 18+ CVE 上测试：

- tag judge accuracy
- latency
- error rate
- prompt token 消耗
- evidence usefulness

### P4：再接 Step3

只有 P0-P3 通过后，Step3 才能使用：

```text
root_cause_vet.json
vet_evidence_graph.json
vet_admission_input.json
```

## 16. 当前设计判断

当前 Step2 的最重要目标不是让 agent “写得更详细”，而是让 Step2 生成可验证、可评分、可压缩、可跨版本使用的 VET。

换句话说，Step2 的核心创新应是：

> deterministic root-cause extraction + agent semantic refinement + dataset-level evidence admission。

如果这一步做不好，Step3 的 scheduler 只能继续保守地激活大量 line，probe 成本无法从根上降下来。

## 17. P1-B Admission Gate 实测结果

本节记录 2026-05-19 对 P1-B `expanded_27` 的实际 admission gate 测试。该测试不是最终 Step2 主流程，只用于回答一个关键问题：

> Step2 agent 输出的 `CERT_ABSENT` / `CERT_FIXED` 候选是否能直接进入 Step3 hard certificate？

测试脚本：

```text
E:\AI\Agent\workflow\VulnVersion\tests\simulate_vet_admission_gate.py
```

运行命令：

```powershell
cd E:\AI\Agent\workflow\VulnVersion
python tests\simulate_vet_admission_gate.py --review-dir tests\vet_taxonomy_case_review\expanded_27 --dataset DataSet\BaseDataOrder.json --repo-root repo --out tests\vet_admission_gate_p1b --max-unaffected-per-case 30
```

输出目录：

```text
E:\AI\Agent\workflow\VulnVersion\tests\vet_admission_gate_p1b\
```

输出文件：

| 文件 | 内容 |
| --- | --- |
| `summary.json` | admission strategy 总表 |
| `admission_decisions.json` | 每个 case 的 gate blocker 和 clear 统计 |
| `wrong_certificate_cases.json` | 会错误清除 GT affected tag 的 case/tag |
| `per_case.jsonl` | 每个 CVE 的逐 case 结果 |
| `report.md` | 简短报告 |

### 17.1 测试口径

由于 P1-B 是 27 个 case 的 admission 检查，不是全量 Step3 run，本轮采用以下口径：

- 对每个 case，所有 mapped GT affected tags 全量检查。
- 对 unaffected release tags 做确定性抽样，每个 case 最多 30 个。
- 因此 `wrong_cleared_affected_tags` 是精确的；`true_cleared_unaffected_tags` 是抽样估计。
- GT 只用于 simulator oracle，不进入 Step2/Step3 真实规划。

### 17.2 策略结果

| strategy | cleared tags | true clear | wrong affected clear | clear precision | wrong cases | 判断 |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `raw_agent_flags_any` | 891 | 521 | 370 | 0.584736 | 10 | 绝对不能直接用 |
| `raw_fixed_token` | 593 | 237 | 356 | 0.399663 | 10 | `fix token present -> fixed` 严重不安全 |
| `raw_absent_scope_or_vuln` | 349 | 335 | 14 | 0.959885 | 2 | 比 fixed 安全，但仍会漏报 |
| `strict_fixed_token` | 106 | 74 | 32 | 0.698113 | 3 | 加 gate 后仍不安全 |
| `strict_fixed_token_and_vuln_absent` | 0 | 0 | 0 | 0.000000 | 0 | 过严，无覆盖 |
| `strict_absent_scope_only` | 46 | 46 | 0 | 1.000000 | 0 | 当前唯一可保留为候选的安全方向 |
| `strict_gate_any` | 152 | 120 | 32 | 0.789474 | 3 | 因 fixed 分支仍不安全 |
| `ultra_strict_gate_any` | 46 | 46 | 0 | 1.000000 | 0 | 等价于 scope-absent-only，有安全性但覆盖低 |

### 17.3 关键结论

1. P1-B 的 raw agent certificate 不能直接进入 Step3。`raw_agent_flags_any` 会错误清除 370 个 GT affected tags。
2. `CERT_FIXED` 当前不安全。即使经过 uncertainty、negative evidence、source refs、admission requirements 等严格 gate，`strict_fixed_token` 仍错误清除 32 个 GT affected tags。
3. `fix token present` 不是 fixed 的充分条件。实测 wrong case 中存在 affected tag 同时命中 vulnerable token 和 fix token 的情况，例如 FFmpeg / CVE-2020-22019。
4. `CERT_ABSENT` 只有在 scope file 明确不存在时表现为安全候选：`strict_absent_scope_only` 在 P1-B 上 0 wrong affected clear，但覆盖只有 46 个 sampled clear tags / 3 个 case。
5. `vulnerable token absent` 不能直接作为 absent certificate。`raw_absent_scope_or_vuln` 仍错误清除 14 个 affected tags。
6. 当前 admission gate 的正确方向是：先允许 VET evidence 做 priority / prompt context；hard certificate 只保留极窄的 scope-absent 候选，并且必须继续扩大样本验证。

### 17.4 Gate blocker 分布

| blocker | count |
| --- | ---: |
| `absent:negative_evidence_missing` | 12 |
| `absent:quality_uncertainty` | 12 |
| `absent:uncertainty_present` | 12 |
| `fixed:negative_evidence_missing` | 12 |
| `fixed:quality_uncertainty` | 12 |
| `fixed:uncertainty_present` | 12 |
| `absent:agent_did_not_allow_cert_absent` | 9 |
| `absent:line_risk_signals_missing` | 2 |
| `fixed:agent_did_not_allow_cert_fixed` | 2 |

这些 blocker 说明当前 Step2 的问题已经不是 JSON 格式，而是证据准入语义还不安全。

### 17.5 长期关注的 8 个精度风险点

以下 8 个风险点必须长期记录，并在后续 Step2/Step3 中逐项通过实验验证：

| 风险点 | 对全局精度的影响 | 当前处理原则 |
| --- | --- | --- |
| 错误 `CERT_ABSENT` | 直接把 affected tag 清成 NOT_AFFECTED，造成 FN | 只允许极窄的 scope-file-absent 候选继续测试 |
| 错误 `CERT_FIXED` | fix token 泛化错误，造成大量 FN | 当前禁止进入 hard certificate |
| `negative_evidence` 缺失 | 无法证明“不存在漏洞条件” | 作为 admission blocker |
| `source_refs` 不完整或不可复核 | agent 结论不可审计 | 只能 priority-only |
| large patch context 不全 | root cause 抽象偏移 | 需要 Step1 packet + read-only git tool 补证 |
| multi-commit 语义混杂 | wrapper/backport/composite 混淆，污染 VET | 默认 OR evidence bundle，复杂情况只加 risk flag |
| taxonomy 过细但无 admission | 论文上好看但工程不稳 | archetype 不等于 certificate |
| `line_risk_signals` 为空 | Step3 scheduler 无法用 VET 降 probe | 作为 Step3 priority blocker |

### 17.6 对 Step2 schema 的直接修改要求

下一版 Step2 输出必须拆为两层：

```text
reviewed_vet:
  root-cause taxonomy
  vulnerability mechanism
  fix mechanism
  guard conditions
  source refs

admission_evidence:
  hard_certificate_candidates
  priority_only_evidence
  forbidden_hard_certificates
  negative_evidence
  uncertainty
  admission_requirements
  admission_status
```

规则：

- VET 仍然是总的漏洞存在性定理，不被 `reviewed_vet` / `admission_evidence` 替代。
- `reviewed_vet` 是 VET 的语义层。
- `admission_evidence` 是 VET 的可用性和安全策略层。
- 所有 evidence 默认 `priority_only`。
- `CERT_FIXED` 当前禁止 hard use。
- `CERT_ABSENT` 仅允许 scope-file-absent 作为候选继续扩大验证。

### 17.7 当前下一步

1. 修改 Step2 schema，显式加入 `admission_status` 和 `allowed_uses`。
2. 将 `CERT_FIXED` 从 hard certificate 候选中降级为 priority/prompt context，直到新的 root-cause sequence gate 证明安全。
3. 扩大 `strict_absent_scope_only` 到 81-case，再观察是否仍为 0 wrong affected clear。
4. 设计更强的 fixed gate：不能只看 fix token，必须验证 fix guard 与 vulnerable operation 的局部绑定，并证明 vulnerable condition 被破坏。
