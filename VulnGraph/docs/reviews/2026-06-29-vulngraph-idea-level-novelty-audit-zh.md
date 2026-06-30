# VulnGraph Idea-Level Novelty Audit 中文沉淀

日期：2026-06-29

来源：
- Novelty Audit Session: `019ed49c-ecdf-77d0-b5f2-0b04fed90999`
- 本文档整合：novelty 审计结果 + 当前规划/Review Agent 的分析判断

## 1. 审计边界

这份文档审计的是 **paper idea-level novelty**，不是当前源码完成度。

必须区分四件事：

| 维度 | 含义 |
|---|---|
| Idea-level novelty | 这个想法相对现有工作是否足够新 |
| Implementation readiness | 当前源码是否已经实现 |
| Evaluation readiness | 当前是否已有足够实验支撑 |
| Paper-claim readiness | 当前能否写进 contribution / abstract / introduction |

之前的审计一度把“尚未实现”直接等价为“没有 novelty”，这个口径不准确。未实现只能说明不能写成当前结果 claim，但不能直接否定 idea 本身。

正确审计方式是：

```text
这个 idea 是否新？
它和 baseline 的边界在哪里？
reviewer 会如何攻击？
要怎样定义和实验验证，才能成为 ICSE contribution？
```

## 2. Executive Idea-Level Verdict

| Novelty | Idea-level verdict | 判断 |
|---|---|---|
| A. Attacker-Condition-Guided Affected-Version Reasoning | `CONDITIONAL_NOVELTY` | 有潜力，但必须从“攻击者 KG”窄化为 tag-local exploit-condition / applicability condition。不能泛泛说 CVE-to-ATT&CK 或安全 KG。 |
| B. Evidence-Constrained Branch-Specific Vulnerability-State Reconstruction | `STRONG_NOVELTY` | 三者中最像 ICSE 主贡献。它把 affected-version identification 从 BIC interval 推断改写为 branch/release DAG 上的 vulnerability/fix state reconstruction，并限制 LLM 只能基于 wrapper-owned evidence 判断。 |
| C. Graph-Backed Continual Adaptation | `WEAK_OR_INCREMENTAL` | 作为长期系统设计有价值，但 graph memory、feedback adaptation、self-improving agent 都有大量相近工作。除非做 chronology-safe evaluation，否则不宜作为主 novelty。 |

最终判断：

```text
B 是主贡献。
A 可以作为辅助 novelty 或 ablation。
C 暂时降级为 future work 或长期扩展。
```

### 2.1 Per-Novelty Readiness Matrix

这个矩阵不是重新做源码审计，而是把 **idea-level novelty** 和 **当前能否写成论文 claim** 分开。一个 idea 可以有 novelty，但仍然不能写成 result claim。

| Novelty | Idea-level novelty | Implementation readiness | Evaluation readiness | Paper-claim readiness |
|---|---|---|---|---|
| A. Attacker-Condition-Guided Affected-Version Reasoning | `CONDITIONAL_NOVELTY`：如果严格定义为 tag-local exploit-condition / applicability-condition affectedness，有潜在新意。 | 不能假设已完成；即使已有 root-cause / guard / predicate 字段，也不足以等价为 attacker-condition reasoning。 | 需要专门的 condition-sensitive cases 与人工标签；普通 affected-version F1 不能证明 A。 | 不能写成主结果；可以写成概念定义、动机、可选 schema、ablation hypothesis。 |
| B. Evidence-Constrained Branch-Specific Vulnerability-State Reconstruction | `STRONG_NOVELTY`：最能和 affected-version 文献拉开距离，核心是 branch/release DAG 上的 vulnerability/fix state reconstruction。 | 可以作为系统主线推进；但各模块是否完整实现，不影响 idea-level novelty 判断。 | 必须有 event-level、boundary-level、tag-state-level 标签和 baseline ablation。 | 可作为主 contribution 的目标表述；但在实验证据前，不能写成“已证明优于 baseline”。 |
| C. Graph-Backed Continual Adaptation | `WEAK_OR_INCREMENTAL`：domain-specific gated prior 有价值，但 graph memory / feedback adaptation / skill memory 方向已有大量相近思想。 | 可以作为系统扩展点；不能仅凭 graph store / memory schema 声称 continual adaptation。 | 必须做 chronology-safe split、memory promotion gate、negative-transfer audit。 | 不建议进 abstract / main contribution；最多放 Discussion / Future Work，除非有独立实验。 |

### 2.2 Baseline Collision Table（完整）

| Novelty | 最危险 baseline | Baseline 已经做了什么 | VulnGraph idea 必须比它多什么 | Reviewer 可能如何攻击 |
|---|---|---|---|---|
| A | VERCATION / CaVulner | 已经用 LLM、静态分析、上下文信息判断 vulnerability-relevant code 与 vulnerable versions。 | 必须证明不是普通 context-aware matching，而是 trigger / precondition / sink / reachability condition 改变了 tag-level affectedness verdict。 | “你只是把 vulnerability semantics 换名成 attacker condition。” |
| A | ATT&CK-to-CVE / NEXUS | 已经从 CVE / CTI 文本中抽取 attack behavior、TTP、CVE-to-technique mapping，并有反馈/适配机制。 | 必须证明任务不是 CVE-to-TTP，而是 tag-local exploitability/applicability condition，用于 affected-version reasoning。 | “这只是把 ATT&CK/NEXUS 风格的攻击语义塞进 prompt。” |
| A | KRYSTAL / D3FEND | 已有 typed security KG、attack/defense/provenance reasoning、artifact-mediated security relations。 | 必须把 attacker condition 绑定到 release tag 的源码/构建/路径可达证据，而不是泛泛 KG traversal。 | “安全 KG 和 typed evidence 已经很多，你没有新的推理模型。” |
| A | p01 affected-version benchmark | 已经指出 affected-version task、code presence、branch/multi-patch 等困难。 | 必须展示 code-present-but-not-affected 或 condition-changed 的特定错误类别，并证明 A 能修复。 | “p01 的问题定义已经够了，你只是换了动机语言。” |
| B | p01 affected-version paper | 已经定义 affected-version identification、两级 metric、tracing/matching taxonomy、failure categories。 | 必须在 p01 任务定义上提出新的 state reconstruction formulation，并在同类 metric 下验证。 | “你只是重新包装 affected-version benchmark 的 stage taxonomy。” |
| B | V-SZZ | 已经从 fixing commits / inducing commits 推 affected version ranges，并考虑 duplicated changes。 | 必须超越 BIC interval，显式处理 branch-local vulnerable/fix predicate、equivalent fix、backport、partial fix、unknown。 | “你就是 V-SZZ 加一个 LLM Judge。” |
| B | TDSC affected-version methods | 已经使用 patch、developer logs、version tree 判断 affected versions，并讨论 repatch/unpatch。 | 必须证明 Git DAG state propagation 在 branch/backport/repatch/partial-fix 场景下更可验证。 | “developer-log/version-tree 方法已经做了版本状态推理。” |
| B | VERCATION / CaVulner | 已经做 context-aware vulnerable-version identification，含 LLM/static/code semantics。 | 必须证明 evidence-constrained event/state pipeline 优于直接 vulnerable-code semantic matching。 | “你没有比 LLM/static vulnerable-version 方法多出本质机制。” |
| B | LLM4SZZ / MAS-SZZ / AgentSZZ / Agentic-SZZ / Beyond Blame | 已经做 LLM/agentic/root-cause/temporal-KG BIC discovery 和 history search。 | 必须强调输出不是 BIC，而是 release-tag vulnerability/fix state；LLM 只能在 wrapper-owned evidence 上判断 candidate event role。 | “Root Cause Agent + SZZ + Judge 是已有 agentic SZZ 的模块拼装。” |
| B | FIRE / MOVERY / VUDDY / V1SCAN / VULTURE / ReDeBug | 已经用 staged filtering、clone/signature/hash/function-level matching 寻找 vulnerable code 或 unpatched clones。 | 必须证明 code presence/signature match 不等于 affectedness，并且 branch-state reconstruction 能减少这些方法的 FP/FN。 | “你的 affectedness 最终还是代码匹配；matching baselines 已经覆盖。” |
| C | NEXUS | 已经有 CVE-to-TTP 的 analyst feedback、label adjustment、adaptation / future prediction 叙事。 | 必须做 affected-version-specific memory：repo/CWE/root-cause/patch/failure pattern prior，并证明 chronology-safe future-case gain。 | “feedback adaptation 已有，你只是换到 affected-version task。” |
| C | KRYSTAL / D3FEND / ATT&CK-to-CVE KG | 已有 security KG、typed evidence、graph traversal、ontology-mediated reasoning。 | 必须证明 graph memory 不是存储层，而会改变 Root Cause / SZZ Anchor / Judge 的后续决策。 | “KG 是工程基础设施，不是算法贡献。” |
| C | Reflexion / Voyager / Skill Memory / Graph-RAG 类外部工作 | 已有 self-reflection、skill reuse、memory retrieval、agent improvement 的通用框架。 | 必须给出 verifier-gated、label-leakage-free、negative-transfer-aware 的 affected-version 专用 memory 机制。 | “这就是 graph-RAG / skill memory，不是 ICSE novelty。” |
| C | p01 / V-SZZ / direct affected-version baselines | 已经提供 affected-version task 与 baseline performance frame。 | 必须证明 memory 不只是让系统更快或更稳定，而是提升 future affected-version accuracy / NMR / F1。 | “即使有 memory，也没有证明它改善核心任务。” |

注：Reflexion / Voyager / Skill Memory / Graph-RAG 类工作在当前本地 reference corpus 中未形成专门目录；它们应作为后续 Related Work 补充，而不是声称已经被本地 corpus 完整覆盖。

## 3. Novelty A: Attacker-Condition-Guided Affected-Version Reasoning

### 3.1 原始想法

不是普通 CVE 文本分析，也不是 CVE-to-ATT&CK 映射。核心 idea 应该是：

```text
从攻击者视角抽取 trigger / exploit precondition / sink / reachability condition，
并将这些条件用于判断某个 release tag 是否真正 affected。
```

也就是说，一个 release 是否 affected，不只取决于 vulnerable code 是否存在，还取决于漏洞触发条件是否仍成立。

### 3.2 最危险 baseline

| Baseline 类型 | 攻击点 |
|---|---|
| VERCATION / CaVulner | 已经用 LLM/static/context 判断 vulnerability-relevant code 与 vulnerable versions。 |
| ATT&CK-to-CVE / NEXUS | 已经从 CVE 文本抽取 attack behavior / TTP / CTI mapping。 |
| KRYSTAL / D3FEND | 已有安全 KG、typed evidence、attack/defense reasoning。 |

### 3.3 Reviewer 会怎么喷

Reviewer 可能会说：

```text
“attacker condition 只是 vulnerability semantics / exploitability / context-aware matching 的换名词。”
```

或者：

```text
“你只是把攻击图谱塞进 prompt，没有证明它改变 affected-version verdict。”
```

### 3.4 可辩护表述

不要主打 “attacker KG”。更稳的术语是：

```text
condition-aware affectedness
```

建议 contribution wording：

> We define condition-aware affectedness: a release is affected only when the vulnerable code predicate and attacker-relevant trigger, precondition, sink, or reachability condition are jointly satisfied in tag-local evidence.

### 3.5 需要的证据

要让 A 成为 paper contribution，至少需要：

- 数据：code-present-but-not-exploitable、precondition changed、sink unreachable、guard/build condition changed 的 cases。
- 人工标签：每个 tag 的 trigger/precondition/sink/reachability 是否成立。
- Baseline：code-text matching、context-aware vulnerable-version matching、without-attacker-condition ablation。
- Metric：FP reduction、condition extraction precision/recall、affected-version Exact/NMR/F1。

Failure Conditions：

- 如果 attacker condition 只是在 prompt 中提供额外解释，但没有改变 affected-version verdict，则 A 不能作为 contribution。
- 如果 condition extraction 无法稳定落到 tag-local evidence，例如只停留在 CVE 文本或 ATT&CK/TTP 层面，则 A 会被视为 CTI/KG 复用。
- 如果 code-present-but-not-exploitable / condition-changed cases 很少，或者 ablation 中 FP reduction 不显著，则 A 应降级为 motivation/future work。
- 如果人工标签无法区分 “vulnerable code present” 与 “exploit condition satisfied”，则 A 的理论定义不具备可评估性。

### 3.6 当前 paper 处理建议

当前不要把 A 写成主贡献。可以作为：

- 背景中的问题动机；
- Approach 中的可扩展条件 schema；
- Evaluation 中的后续 ablation；
- Future work 中的 attacker-condition KG 模块。

## 4. Novelty B: Evidence-Constrained Branch-Specific Vulnerability-State Reconstruction

### 4.1 原始想法

核心不是 “LLM 做 SZZ”，也不是 “找 BIC”。

真正的 idea 是：

```text
Root Cause Agent 基于真实源码和 patch evidence 选择 pre-fix anchors；
改进 SZZ 在 Git DAG 上重建 history event；
Judge 判断 candidate event 类型；
最后在 branch/release DAG 上传播 vulnerability/fix state；
最终输出 affected_versions。
```

关键约束：

```text
LLM 不能自由编造路径、行号、SHA、BIC。
LLM 只能基于 wrapper-owned evidence 和 candidate_id 做判断。
```

### 4.2 最危险 baseline

| Baseline | 已经做了什么 | VulnGraph 必须多什么 |
|---|---|---|
| V-SZZ | 从 fixing/inducing commits 推 affected version ranges。 | 不能只是 BIC interval；必须证明 branch-local vulnerability/fix state reconstruction 更强。 |
| TDSC affected-version | 使用 patch/developer logs/version tree 识别 affected versions。 | 必须明确 Git DAG state propagation 如何处理 backport/partial fix/equivalent fix。 |
| VERCATION / CaVulner | LLM/static/context vulnerable-version identification。 | 必须证明 evidence-constrained event/state pipeline 比直接语义匹配更稳。 |
| LLM4SZZ / MAS-SZZ / AgentSZZ / Beyond Blame | LLM/agentic/root-cause/temporal-KG BIC discovery。 | 必须强调输出不是 BIC，而是 release-tag affected state。 |

### 4.3 Reviewer 会怎么喷

Reviewer 可能会说：

```text
“你就是 V-SZZ + LLM + graph database。”
```

或者：

```text
“Root Cause Agent + SZZ + Judge 都已有，你只是拼装。”
```

因此，B 必须避免写成“多模块流水线”。它必须被定义成一个明确的科学问题：

```text
affected versions = branch-specific vulnerability/fix state over release DAG
```

### 4.4 可辩护表述

建议主 contribution wording：

> We formulate affected-version identification as evidence-constrained branch-state reconstruction over a release DAG. The method reconstructs typed history events from patch-bound root-cause anchors, classifies candidate event roles using only wrapper-owned evidence, and propagates vulnerability/fix state to release tags with explicit unknowns.

更短版本：

> VulnGraph treats affected-version identification as branch-specific vulnerability-state reconstruction, rather than BIC-to-version interval inference.

### 4.5 需要的证据

要让 B 成为主贡献，需要：

- 人工标签：
  - true pre-fix anchor
  - true history event type
  - true introduction/prerequisite/refactor/fix-series/unrelated label
  - tag-level affected/unaffected/unknown state
- Baseline：
  - raw blame
  - blame `-w/-M/-C`
  - V-SZZ-like BIC-to-tag reachability
  - patch-signature matching
  - LLM4SZZ/MAS-SZZ/AgentSZZ style BIC candidate baseline
  - p01 affected-version baselines
- Metric：
  - event Recall@1/@3/@5
  - boundary top-1 / MRR
  - affected-version Exact Accuracy
  - NMR
  - micro Precision/Recall/F1
  - unknown rate
  - branch/backport/add-only subset performance

Failure Conditions：

- 如果 event Recall@k 不显著优于 raw blame、`-w/-M/-C` blame union 或 V-SZZ-like candidate generation，则 Root Cause + SZZ Anchor 不是有效 novelty。
- 如果 Judge boundary top-1 / MRR 不优于 deterministic ranking 或 raw top-1，则 Judge 只能作为解释模块，不能作为核心方法贡献。
- 如果 branch-specific state propagation 在 affected-version Exact/NMR/micro-F1 上不优于 BIC-to-tag reachability 或 patch-signature matching，则 B 不能成立为主 contribution。
- 如果 unknown rate 过高，导致方法主要输出 unknown，而 confirmed affected/unaffected precision 又无法显著提升，则 B 会被 reviewer 认为是保守 ledger，不是有效识别方法。
- 如果人工标签显示大部分错误来自 root-cause predicate 或 event type，本方法必须把贡献改写为 failure analysis / infrastructure，而不是 affected-version breakthrough。

### 4.6 当前 paper 处理建议

B 应该是论文主线。

Method、Evaluation、Introduction 都应该围绕 B 展开：

```text
Root Cause Predicate
→ Evidence-Constrained Anchor
→ Git History Event Reconstruction
→ Judge Boundary Event
→ Branch-Specific State Propagation
→ Release Tag Projection
→ affected_versions
```

## 5. Novelty C: Graph-Backed Continual Adaptation

### 5.1 原始想法

核心 idea 不是“把数据存进 Neo4j”，而是：

```text
同 repo / 同 CWE / 同 root-cause pattern / 同 patch pattern / 同失败模式
可以沉淀为后续 Root Cause / SZZ Anchor / Judge 的 reusable prior。
```

这些 prior 必须经过 verifier 或人工 gate，不能直接污染后续判断。

### 5.2 最危险 baseline

| Baseline 类型 | 攻击点 |
|---|---|
| NEXUS | 已有 analyst feedback / adaptive correction。 |
| KRYSTAL / D3FEND / ATT&CK KG | 已有 security KG、typed evidence、graph reasoning。 |
| Reflexion / Voyager / Skill Memory / Graph-RAG 类工作 | 已有 memory / skill / self-improving agent 框架。 |

### 5.3 Reviewer 会怎么喷

Reviewer 可能会说：

```text
“这就是 feedback database / graph-RAG / 经验规则库，不是新算法。”
```

或者：

```text
“你没有证明 memory 对未来 CVE 有帮助，也没有防止 label leakage。”
```

### 5.4 可辩护表述

不要说 “self-evolving”。这个词风险太高。

更稳的表述是：

> We study whether verifier-gated cross-case priors over repository, CWE, root-cause, patch, and failure patterns can improve future affected-version decisions under chronology-safe evaluation.

### 5.5 需要的证据

要让 C 成为 contribution，需要：

- 时间切分的 CVE stream。
- No-memory vs retrieval-only vs ungated-memory vs verifier-gated-memory ablation。
- Memory promotion gate。
- Negative-transfer analysis。
- Chronology leakage audit。
- 同 repo/CWE/pattern 的 future-case delta。

Failure Conditions：

- 如果 chronology-safe split 下 memory 不能提升 future-case affected-version Exact/NMR/F1，则 C 不能作为 contribution。
- 如果提升主要来自 label leakage、同一 CVE 的重复信息、或人工 hindsight pattern，则 C 应直接删除。
- 如果 ungated memory 与 verifier-gated memory 差异不明显，则 verifier gate 的方法价值不足。
- 如果 negative transfer 明显，例如错误 prior 污染后续 Root Cause / SZZ Anchor / Judge，且无法被 gate 捕获，则 C 不仅不 novel，还会成为系统风险。
- 如果 memory 只能减少 token/cost，而不能改善 affected-version correctness，则最多是 engineering optimization。

### 5.6 当前 paper 处理建议

当前不建议把 C 放主 contribution。

可以作为：

- Future work；
- Discussion；
- System extensibility；
- 如果后续实验完成，再作为单独 contribution。

## 6. 推荐的最终贡献结构

不建议三条 novelty 并列写。

推荐结构：

### C1 主贡献

> We formulate affected-version identification as evidence-constrained, branch-specific vulnerability-state reconstruction over release histories.

### C2 支撑贡献

> We design a reproducible pipeline that converts patch-bound root-cause evidence and Git history events into auditable tag-level vulnerability-state ledgers.

### C3 可选/辅助贡献

> We introduce condition-aware affectedness as an extension point for cases where code presence alone is insufficient.

### Future Work

> Graph-backed verifier-gated continual adaptation across repositories, CWEs, root-cause patterns, and patch patterns.

## 7. 不安全写法与安全写法

| 不安全写法 | 问题 | 更安全写法 |
|---|---|---|
| VulnGraph uses attacker KG to identify affected versions. | 当前太宽，容易撞 ATT&CK/NEXUS/KG 工作。 | VulnGraph can model condition-aware affectedness when tag-level code presence is insufficient. |
| VulnGraph is a self-evolving vulnerability graph. | 当前没有 chronology-safe adaptation evidence。 | The graph schema can store verifier-gated cross-case priors; adaptation is evaluated separately. |
| VulnGraph improves SZZ with LLM agents. | MAS-SZZ/LLM4SZZ/AgentSZZ 会直接攻击。 | VulnGraph uses evidence-constrained history-event reconstruction as an intermediate step toward affected-version state reasoning. |
| We identify BICs and then affected versions. | 这会把任务退化成传统 SZZ。 | We separate candidate history-event judgment from branch-specific release-state projection. |
| Semantic equivalence verification. | 当前若无 AST/CFG/dataflow 支撑，容易过度承诺。 | Predicate/fix-state evidence, with explicit unknowns and auditable failure states. |

## 8. 对论文写作的直接影响

### Introduction

Introduction 的贡献列表应避免写三条并列的大 novelty。

建议写：

1. affected-version identification should be modeled as branch-specific vulnerability-state reconstruction, not BIC interval inference.
2. VulnGraph constrains LLM/agent judgment to wrapper-owned evidence and typed history events.
3. VulnGraph supports condition-aware affectedness and graph-backed reuse as extensibility points, with evaluation separated from the core method.

### Background

Background 只需要铺垫：

- affected versions 不等于 BIC/VIC；
- fixing patches 不等于 vulnerability state；
- branch/backport/release DAG 会破坏线性区间推断；
- code presence alone may be insufficient when exploit conditions change.

不要在 Background 里宣传 KG 或 self-evolution。

### Related Work

Related Work 必须专门防守：

- p01 affected-version benchmark；
- V-SZZ / TDSC / VERCATION / CaVulner；
- LLM4SZZ / MAS-SZZ / AgentSZZ / Beyond Blame；
- ATT&CK-to-CVE / NEXUS / KRYSTAL / D3FEND；
- graph memory / self-improving agent work。

### Method

Method 必须围绕 B，而不是 A/C：

```text
Root Cause Predicate
→ Evidence-Constrained Anchor
→ History Event Reconstruction
→ Event Role Judgment
→ Branch-Specific Vulnerability/Fix State
→ Release Tag Projection
```

### Evaluation

Evaluation 必须证明 B：

- candidate event Recall@k；
- Judge boundary accuracy/MRR；
- affected-version Exact/NMR/micro-F1；
- add-only/multi-file/multi-branch/backport subset；
- against p01 baselines and SZZ/LLM/agent baselines。

A 和 C 只能在 Evaluation 中作为 ablation 或 future evaluation，不能抢主线。

## 9. 当前工程优先级

根据 novelty 审计，当前工程优先级应服务 B：

```text
manual event labels
→ event Recall@k
→ Judge boundary validation
→ branch-specific affected-version conversion
→ p01 baseline comparison
```

不要优先做：

- 大 KG；
- self-evolution；
- attacker KG；
- 继续堆 converter 规则；
- 没有人工标签的 Judge 调参。

原因：

```text
B 不立住，A/C 都无法拯救 paper。
```

## 10. 最终结论

当前最可辩护的论文定位是：

> VulnGraph is an evidence-constrained, branch-specific vulnerability-state reconstruction framework for affected-version identification.

当前最强 novelty 是：

> 把 affected-version identification 从 BIC-to-version interval inference 改写为 Git DAG 上的 branch-specific vulnerability/fix state reconstruction，并通过 wrapper-owned evidence 约束 LLM/agent 判断。

当前最不应过度宣传的是：

- attacker KG；
- graph-backed self-evolution；
- generic LLM/SZZ pipeline；
- semantic equivalence；
- BIC correctness。

最终 paper 建议：

```text
主贡献押 B。
A 作为辅助/ablation。
C 暂时 future work。
```
