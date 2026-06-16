# VulnVersion Agent Enhancement Design

本文档是 VulnVersion 中 Agent 增强方案的长期维护文档。凡是后续修改 Agent prompt、Agent runtime、memory schema、self-evolution pipeline、skill injection、harness adapter 或相关实验配置，都必须同步更新本文档。

源码落地状态由配套文档 `SystemDesign/Architecture/Develop/Agent-Enhance-Status.md` 动态维护。每次源码改动后，应在 `E:\AI\Agent\workflow\VulnVersion` 下运行 `cmd /c "python tests\check_agent_enhance_status.py"` 更新当前状态判断。

## 1. 设计目标

VulnVersion 的核心任务是基于 CVE、CWE、fix commit、Git 历史和源码文本，识别一个 CVE 影响的版本范围。Agent 在系统中不是通用聊天助手，而是面向漏洞版本验证的证据导航器、漏洞定理归纳器和版本判定器。

当前 Agent 主要参与三个阶段：

| 阶段 | Agent 责任 | 不负责内容 |
|---|---|---|
| Step 1: Vuln Chunk Recognition | 从 fix patch 中识别与漏洞修复直接相关的 chunk | 不做版本范围判定 |
| Step 2: Root Cause / RCI Extraction | 从相关 chunk、CVE 描述和源码上下文中提取 root cause、anchor、vuln/fix predicates、guards | 不枚举 tag，不直接输出 affected version |
| Step 3: Version Impact Confirmation | 对给定 tag 进行漏洞存在性判定，输出 evidence-backed verdict | 不负责 tag plan，不负责选择扫描范围 |

本方案的目标是全方位增强以上 Agent 使用方式，形成面向 VulnVersion 的专用 Agent 自进化体系：

1. 将 Agent 运行经验转化为类型化 memory，而不是仅保存原始日志。
2. 从成功和失败轨迹中形成 procedural memory，用于复用验证流程。
3. 将 memory 操作本身做成可选择、可评估、可进化的 memory skills。
4. 将高置信经验晋升为可注入 prompt 的 skills 或可执行 artifacts。
5. 建立 backend-agnostic harness，使 OpenCode、Claude Code、Codex 等 Agent 后端可公平对比。
6. 通过 verifier-gated self-evolution 避免错误经验污染系统。

## 2. 论文启发到 VulnVersion 的映射

本文档综合以下方向形成方案：

| 方向 | 论文启发 | VulnVersion 映射 |
|---|---|---|
| Agent memory survey | memory 应从 forms、functions、dynamics 设计 | 设计 factual / experiential / working / procedural / artifact memory |
| Procedural memory | 从轨迹中提取可复用过程，减少重复探索 | 将 tag verification trajectory 蒸馏成漏洞验证步骤 |
| MemSkill | memory 操作本身可由 controller 选择，并由 hard cases 进化 | 设计 INSERT/UPDATE/DELETE/PROMOTE/SUPPRESS 等 memory operation skills |
| AutoSkill / Trace2Skill / SkillRL | 从成功和失败经验中提炼可迁移 skill | 从 FP/FN/UNK/TIMEOUT 中提炼 Stage1/2/3 skills |
| CoEvoSkills | skill 生成需要 surrogate verifier 和 oracle gate | 所有 skill/memory/artifact 晋升都必须经过验证门控 |
| SkillsBench | curated skills 有效，自生成 skills 可能负收益 | self-generated skill 不能直接注入，必须评估、降权、废弃 |
| Artifact-centric evolution | 将经验沉淀为可执行 artifact，而不是只写进 prompt | 生成 repo adapters、predicate repair rules、anchor relocation policies |

## 3. 总体架构

VulnVersion Agent 增强层命名为 **VulnMem-Agent Layer**。

```text
VulnVersion Core
  Step 1: Semantic Patch / Vuln Chunk Recognition
  Step 2: Root Cause and RCI Extraction
  Step 3: Tag-level Version Impact Confirmation
        |
        v
Agent Runtime Interface
  OpenCodeRuntime / ClaudeCodeRuntime / CodexRuntime / ReplayRuntime
        |
        v
VulnMem-Agent Layer
  Working Memory
  Factual Memory
  Evidence Memory
  RCI Memory
  Repo Memory
  Line Memory
  Failure Memory
  Procedural Memory
  Skill Memory
  Artifact Memory
        |
        v
Self-Evolution Loop
  Trace Collection
  Error Attribution
  Memory Operation Skill Selection
  Memory Promotion
  Skill Optimization
  Artifact Compilation
  Verifier-Gated Acceptance
```

核心原则：

1. Agent 只输出 evidence-backed structured objects。
2. Memory 不等于日志，必须有类型、作用域、证据来源、可靠性和生命周期。
3. Memory 和 Skills 必须分层：memory 主要用于补全上下文、保留 case-specific / repo-specific / CVE-specific 经验，增强 Agent 的上下文判别能力；skills 只保存可复用、可触发、可验证的规则、流程或操作策略。
4. 可确定性完成的逻辑优先放入 Python artifact，不依赖 Agent 每次重新推理。
5. Agent backend 必须可替换，所有 backend 通过统一 runtime interface 接入。
6. Agent 只做判别，不做 tag plan、扫描顺序规划、边界搜索规划、early-stop 决策或跨 tag 范围推断。

### 3.1 Agent 判别边界与 Planner 分离

VulnVersion 必须保持 **Planner / Judge separation**。Agent 在三个 step 中都是 judge，不是 planner。

```text
Deterministic Planner
  - build tag plan
  - choose release lines
  - choose scan order
  - run ASBS / binary search policy
  - apply early stop
  - aggregate per-tag verdicts into affected range
  - compute metrics against GT

Agent Judge
  - Step1: judge whether a given diff chunk is vulnerability-relevant
  - Step2: judge and formulate root cause / RCI from given evidence
  - Step3: judge whether a given tag is affected using current-tag evidence
```

硬约束：

1. Agent 不得枚举待验证 tags。
2. Agent 不得决定扫描哪些 tags。
3. Agent 不得决定 release line 的遍历顺序。
4. Agent 不得使用邻近 tag、版本号、发布日期、advisory range 直接推出当前 tag verdict。
5. Agent 不得将 boundary memory、ASBS 结果或 early-stop 状态作为漏洞存在性证据。
6. Memory/Skill 可以提示“当前 line 风险高、需要保守判定”，但不能把 planner 的范围推断注入为 verdict 依据。
7. 最终 affected version range 只能由 deterministic aggregation 根据 per-tag verdicts 计算。

文档和源码中凡出现 `plan`、`boundary`、`ASBS`、`early_stop`、`scan order` 的逻辑，默认属于 deterministic planner 或 orchestrator，不属于 Agent prompt 的判定依据。

源码入口也不应保留已经失效的 planner/legacy 兼容参数。若某个 CLI 或 runtime 参数不能真实改变 Stage3 行为，就必须删除或改成显式 `blocked/TODO`，避免实验者误以为它控制了扫描范围、early stop 或二分策略。当前已从 `main.py` / `run_stage3()` / `verify_tags()` 删除 `--all-tags`、`--max-tags`、`--early-stop-n`、`early_stop_n` 和 `bisect_enabled` 等废弃路径；后续如果需要控制 Stage3 成本，应在 deterministic tag plan / probe budget 层新增真实生效的参数，而不是恢复旧兼容字段。

## Agent Judge Capability Enhancement After Step3 Tag Plan Stabilization

Step3 tag plan 已进入 deterministic planner 范畴。后续 Agent enhancement 不再以优化 tag plan、scan order、ASBS 策略或 affected range aggregation 为目标，而应集中增强 Step1 / Step2 / Step3 的 **judge capability**。Agent 的价值不是替代 planner，而是在 planner 给定的局部判别任务中提供更稳定、更可解释、更高准确率的证据判定。

### Judge Capability Focus

当前阶段的 Agent 能力目标收敛为六类：

| 能力 | 目标 | 主要影响阶段 | 典型失败 |
|---|---|---|---|
| evidence localization | 找到与当前 chunk / RCI / tag 判定直接相关的局部源码证据 | Step1/2/3 | repo-wide grep 命中、证据不在生产路径、测试代码误用 |
| root cause alignment | 让 Step1 chunk、Step2 RCI、Step3 verdict 对齐同一漏洞机制 | Step1/2/3 | patch summary 与真实 root cause 脱节 |
| predicate evaluation | 正确判断 vuln/fix predicates 在当前证据范围内是否成立 | Step2/3 | predicate overmatch、predicate undermatch |
| guard/fix adjudication | 区分真正阻断漏洞的 fix/guard 与弱信号、无关 token | Step2/3 | fix token 出现在无关位置导致 false NOT_AFFECTED |
| uncertainty calibration | 在证据不足、冲突、迁移失败或 tool failure 时给出保守不确定性 | Step3 | anchor missing 后过早判定 NOT_AFFECTED |
| JSON/schema stability | 保证输出可解析、字段完整、可 replay、可审计 | Step1/2/3 | malformed JSON、字段缺失、reason/evidence 脱钩 |

每一类能力都必须绑定 case pack、ReplayRuntime 结果和小样本验证指标。没有真实 case 支撑的能力增强只能保持 `hypothesis`，不能进入默认主路径。

### Step1 -> Step2 -> Step3 Judge Chain

三阶段 Agent 判别不是相互独立的 prompt 问题，而是一条误差会向下游传播的 judge chain：

```text
Step1 chunk judgement
  -> selected vulnerability-relevant chunks
  -> Step2 root cause / anchor / predicate / guard induction
  -> Step3 single-tag verdict evidence space
  -> deterministic interval aggregation
```

链式影响：

1. Step1 若把 test/doc/refactor chunk 误判为 relevant，会污染 Step2 的 root cause 归纳。
2. Step1 若漏掉 primary fix chunk，会导致 Step2 缺少关键 vuln/fix mechanism。
3. Step2 若生成过宽 predicates，Step3 容易产生 false AFFECTED。
4. Step2 若把 weak signal 写入 fix_predicates，Step3 容易产生 false NOT_AFFECTED。
5. Step2 若缺少 `anchor_at_vuln`、alternative tokens 或 rename hints，Step3 更容易 anchor missing。
6. Step3 的准确率不只取决于 Stage3 prompt，还取决于 Step1/2 是否给出了可判别的 root cause、anchor、predicate 和 guard。

因此，Agent enhancement 的评估不能只看最终 tag verdict。必须同时记录：

```text
chunk role quality
RCI quality
predicate localization
guard reliability
tag judge accuracy
downstream FP/FN attribution
```

### VulnVersion-specific Memory / Skill / Artifact Mapping

Agent memory、skills 和 self-evolution 必须落到 VulnVersion 的真实对象上，不能停留在泛化表述。

| 机制 | VulnVersion 中的具体内容 | 用途 |
|---|---|---|
| RepoMemory | path alias、tag style、rename pattern、directory convention、test/doc path filters | 补全 repo 导航上下文，降低 anchor relocation 和路径误判 |
| RCIMemory | predicate reliability、weak signal list、guard risk、anchor reliability、known rename hints | 提升 Step2 RCI 可执行性，减少 Step3 predicate 误判 |
| FailureMemory | FP/FN/UNKNOWN/TIMEOUT/JSON_ERROR/AGENT_ERROR attribution | 为 prompt、memory、skill 和 artifact 优化提供 bottom-up case |
| SkillMemory | 经过 case pack、replay、小样本验证的可复用判别规则 | 约束高频错误模式，例如 generic token overmatch 或 weak fix evidence |
| ArtifactMemory | 可 deterministic 实现的 repo adapter、predicate repair rule、anchor relocation policy | 将稳定规则从 prompt 中移出，降低 Agent 波动和成本 |

Memory 主要补全上下文，Skill 只保存可复用规则。若一条经验只解释某个 CVE 或某个 tag，它应留在 memory 或 trace 中；只有跨 case 复用的判断流程才允许晋升为 skill；若可用 Python 稳定实现，应优先晋升为 ArtifactMemory。

### Evidence-first Admission

所有 Agent enhancement 必须遵守 evidence-first gate：

1. 没有 `agent_enhance_cases/<enhancement_id>/case_index.jsonl`，只能是 `hypothesis`。
2. 没有 ReplayRuntime 回放结果，不能进入 `read_only memory injection`。
3. 没有小样本 OpenCode 验证，不能默认启用。
4. aggregate metric 不足以证明有效，必须同时报告 improved cases、regression cases 和 unchanged failure cases。
5. GT 只能作为离线 oracle signal，不能进入 prompt、memory content、skill content 或 verdict evidence。

该章节是后续实现 memory、skills、自学习和自进化时的收敛边界：先从真实 failure/success cases 中抽取 judge 能力缺口，再决定是否形成 memory、skill 或 artifact。

### Stage3 Prompt v1: Target-tag Theorem Judge

Step3 prompt 的下一轮优化不改变 Step3 的职责。Agent 仍然自主调用 git 查看目标 tag 的真实源码，并输出 `TagVerdict`。变化只在任务收敛方式：不再让 prompt 鼓励开放式 repo navigation，而是让 Agent 围绕 Step2 产出的漏洞存在性定理检查目标 tag 是否满足该定理。

版本定义：

| Prompt | 名称 | 作用 |
|---|---|---|
| `stage3_verdict_v0` | `legacy_navigation` | 已标记为 deprecated A/B baseline；仅用于对照实验和回归定位，不再作为长期优化方向 |
| `stage3_verdict_v1` | `target_tag_theorem_judge` | 目标 tag 定理检查 prompt，以 Step2 root cause、anchor、vuln predicates、fix predicates、guards 为判别中心；prompt 已压缩并显式要求 `git -C <repo_path>` 访问目标仓库 |

v1 的边界：

1. Agent 只判断 planner 给定的一个 tag 是否 affected。
2. Step2 RCI 是漏洞存在性定理和搜索上下文，不是 verdict evidence。
3. Agent 必须读取目标 tag snapshot，例如 `git show <tag>:<path>`；不得用工作区文件代替 tag 代码。
4. `git grep` 只能用于定位候选文件或局部上下文，最终 verdict 需要目标 tag 的代码片段支撑。
5. 不注入 tag plan、scan order、early stop、affected range、neighbor verdict、GT 或 planner state。
6. 若路径缺失，只允许围绕 anchor、predicate、rename/topology 做有界恢复；不能扩大为全仓库漫游式调查。

A/B 评估必须比较：

```text
v0 legacy_navigation
v1 target_tag_theorem_judge

metrics:
  avg_latency_s_per_tag
  avg_tool_calls_per_tag
  stage3_probed_tag_accuracy
  FP / FN / UNKNOWN
  json_parse_failure_count
  improved_cases / regression_cases / unchanged_cases
```

v1 进入默认主路径前，必须满足两类证据：一是静态 trace 中能区分 prompt version/hash；二是真实小样本 OpenCode A/B 中 improved cases 多于 regression cases，并且 Stage3 probed tag accuracy 达到本章定义的准入线。

2026-05-11 的 Stage3-only OpenCode A/B 小样本结果支持继续保留 v1：3 个 CVE、15 个 planner-probed tags 中，v1 相比 deprecated v0 将 UNKNOWN 从 3 降到 0，improved cases 为 3，regression cases 为 0，JSON parse failure 为 0；平均 latency 从 111.17s/tag 降到 52.84s/tag，平均 tool calls 从 32.87/tag 降到 15.33/tag。代价是 prompt 长度从 1855.8 chars/tag 增加到 7386.4 chars/tag，因此 v1 仍需继续做更大样本 cost gate，不能仅凭该小样本删除 v0 legacy prompt。

后续 8-CVE / 40-tag Stage3-only cost gate 显示 v1 的稳定性继续成立：v1 相比 deprecated v0 为 improved=10、regression=0、UNKNOWN 11->1、JSON parse failure=0；平均 latency 从 127.68s/tag 降到 72.84s/tag，平均 tool calls 从 37.35/tag 降到 17.23/tag。虽然 v1 初始 prompt 仍更长（1760.28->7394.53 chars/tag），但完整 OpenCode message JSON 体量从 323132 chars/tag 降到 84821 chars/tag，说明 target-tag theorem judge 通过减少导航和工具输出降低了真实上下文负担。基于该 gate，Stage3 默认 prompt version 可以切换到 v1；v0 只保留为显式 deprecated baseline，用于复现实验和回归定位，暂不作为默认主路径。

## 4. Enhancement Scope and Precedence

Agent 强化必须显式区分作用域。不同层级的 memory、skills、prompt rules、artifacts 不能随意跨层复用，否则会出现 CVE 泄漏、repo 经验污染、backend workaround 被误当作漏洞语义、line boundary hint 被误当作 tag evidence 等问题。

### 4.1 Scope Taxonomy

| Scope | 作用范围 | 典型内容 | 是否可跨任务复用 |
|---|---|---|---|
| Global | 全系统 | AgentRuntime、AgentService、JSON parser、trace、ReplayRuntime、verifier gate、prompt versioning、leakage control | 是 |
| Backend-specific | OpenCode / Codex / Claude 等后端 | SDK capability、tool crash workaround、session policy、JSON repair quirks | 只能同 backend |
| Stage-specific | Step1 / Step2 / Step3 | stage prompt、stage output schema、stage skillbank、stage verifier | 同 stage 复用 |
| CWE-specific | 某类漏洞机制 | CWE-787 bounds check、CWE-200 information exposure、CWE-79 escaping | 可跨 repo/CVE，但不能包含具体 tag 答案 |
| Repo-specific | 某仓库 | tag 风格、路径迁移、目录结构、函数别名、测试目录过滤 | 同 repo 复用 |
| CVE-specific | 单个 CVE | root cause、RCI、anchor、vuln/fix predicates、guards | 只用于该 CVE |
| Release-line-specific | 某 CVE 的某 release line | confirmed paths、frontier risk、line-local discoveries、line-local fix context | 只用于该 CVE line |
| Tag-specific | 单个 tag | prefetched files、grep results、predicate evaluations、verdict evidence | 不复用，只审计 |
| Experiment-specific | 某次实验 | backend config、prompt version、memory mode、skill mode、ablation config | 只用于复现 |

### 4.2 Scope Namespace

所有 memory、skill、artifact、trace 都必须带 namespace。推荐格式：

```text
/global/*
/backend/<backend>/*
/stage/<stage>/*
/cwe/<cwe_id>/*
/repo/<repo>/*
/repo/<repo>/cwe/<cwe_id>/*
/repo/<repo>/cve/<cve_id>/*
/repo/<repo>/cve/<cve_id>/line/<line_id>/*
/repo/<repo>/cve/<cve_id>/tag/<tag>/*
/experiment/<run_id>/*
```

示例：

```text
/stage/stage3/skills/localized_predicate_matching
/cwe/CWE-787/procedures/bounds_check_theorem
/repo/curl/path_aliases/url_handling
/repo/curl/cve/CVE-2020-8169/rci
/repo/curl/cve/CVE-2020-8169/line/7.x/confirmed_paths
/repo/curl/cve/CVE-2020-8169/tag/curl-7_66_0/evidence
```

### 4.3 Scope Retrieval Rules

Memory/Skill retrieval 必须先按 scope 过滤，再做语义检索。

Step1 允许检索：

```text
/global/*
/backend/<backend>/*
/stage/stage1/*
/cwe/<cwe_id>/*
/repo/<repo>/*
```

Step2 允许检索：

```text
/global/*
/backend/<backend>/*
/stage/stage2/*
/cwe/<cwe_id>/*
/repo/<repo>/*
/repo/<repo>/cwe/<cwe_id>/*
/repo/<repo>/cve/<cve_id>/*
```

Step3 允许检索：

```text
/global/*
/backend/<backend>/*
/stage/stage3/*
/cwe/<cwe_id>/*
/repo/<repo>/*
/repo/<repo>/cwe/<cwe_id>/*
/repo/<repo>/cve/<cve_id>/*
/repo/<repo>/cve/<cve_id>/line/<line_id>/*
/repo/<repo>/cve/<cve_id>/tag/<tag>/*
```

Step3 禁止检索为 verdict evidence：

```text
neighboring tag verdicts
affected range aggregation
tag plan
ASBS probe plan
early-stop state
GT affected tag list
```

如果需要注入 release line 风险，只能作为 `risk_hint`，并必须渲染免责声明：

```text
This is a planner-side risk hint. It is not evidence that the current tag is affected or fixed.
Use only current-tag source evidence for the verdict.
```

### 4.4 Precedence and Conflict Resolution

当不同 scope 的信息冲突时，优先级如下：

```text
current-tag git evidence
  > CVE-specific RCI
  > release-line working memory
  > repo-specific memory
  > CWE-specific skill
  > stage/global skill
  > backend workaround
```

解释：

1. 当前 tag 的源码证据永远最高。
2. CVE-specific RCI 只定义本 CVE 的判定定理，不可跨 CVE 使用。
3. Release-line memory 只能帮助定位和风险提示，不能覆盖当前源码证据。
4. Repo-specific memory 只能提供导航和过滤经验。
5. CWE/global skills 只能提供流程指导。
6. Backend workaround 只处理工具/输出问题，不能影响漏洞语义。

硬规则：

```text
planner state != vulnerability evidence
memory hint != current evidence
skill instruction != verdict
GT signal != prompt content
backend workaround != security semantics
```

### 4.5 Promotion Across Scopes

低层 scope 的经验可以晋升到高层 scope，但必须经过 verifier gate。

允许晋升路径：

```text
Tag-specific EvidenceMemory
  -> Release-line LineMemory
  -> CVE-specific ProceduralMemory
  -> Repo-specific RepoMemory
  -> CWE-specific SkillMemory
  -> Global ArtifactMemory
```

晋升要求：

1. Tag -> Line：同一 release line 多个 tag 证据一致。
2. Line -> CVE：多个 line 或关键边界验证支持。
3. CVE -> Repo：同 repo 多个 CVE 支持，且不依赖单个 CVE 的 root cause。
4. Repo -> CWE：多个 repo 支持，且语义属于 CWE 机制而非 repo 结构。
5. CWE -> Global：多个 CWE 或多个任务阶段支持，且不包含漏洞类别特定假设。

禁止晋升：

1. 将单个 CVE 的 affected tags 晋升为 repo/global memory。
2. 将 backend-specific workaround 晋升为 security skill。
3. 将 line boundary inference 晋升为 current-tag evidence rule。
4. 将未验证 self-generated skill 晋升为 verified skill。
5. 将 GT signal 直接转写进 prompt、skill 或 memory content。

### 4.6 Scope-Aware Storage Fields

所有 memory/skill/artifact 至少记录：

```json
{
  "scope_level": "global|backend|stage|cwe|repo|cve|line|tag|experiment",
  "namespace": "/repo/curl/cve/CVE-2020-8169/line/7.x/confirmed_paths",
  "allowed_stages": ["stage3"],
  "allowed_repos": ["curl"],
  "allowed_cwes": ["CWE-200"],
  "allowed_cves": ["CVE-2020-8169"],
  "allowed_lines": ["7.x"],
  "allowed_backends": ["opencode", "codex", "claude"],
  "forbidden_as": ["verdict_evidence"],
  "promotion_status": "none|candidate|verified|promoted|deprecated"
}
```

### 4.7 Scope-Aware Injection Policy

Prompt injection 必须按 scope 渲染，避免混淆：

```text
## GLOBAL PROCEDURE HINTS
General task rules. Not evidence.

## CWE-SPECIFIC SECURITY HEURISTICS
Vulnerability-pattern guidance. Not evidence.

## REPO NAVIGATION MEMORY
Repository structure and path hints. Not evidence.

## CVE-SPECIFIC RCI
The vulnerability theorem for this CVE.

## RELEASE-LINE RISK HINTS
Planner-side risk hints. Not evidence.

## CURRENT-TAG EVIDENCE
Only this section can support the final verdict.
```

只有 `CURRENT-TAG EVIDENCE` 和 Agent 通过 git 工具读取的当前 tag 源码可以直接支撑 Step3 verdict。

## 5. Agent Harness 增强

### 5.1 目标

当前系统通过 OpenCode 调用 Agent。当前源码阶段先完成 **OpenCode-first harness 解耦**，保证现有 OpenCode 流程继续跑通；Claude Code、Codex 只预留 runtime adapter，不作为本阶段实现目标。后续需要支持 OpenCode、Claude Code、Codex 等 Agent 后端做对比实验，因此需要将 Agent harness 抽象为 VulnVersion 内部稳定接口。

重要修正：不同 agent backend 的 skill 机制不相同。OpenCode 在 `E:\AI\Agent\workflow\VulnVersion` 路径运行时，会加载项目下的 `.opencode/skills`；Codex 和 Claude Code 不会自动读取该目录。VulnVersion 自己的 `agent_harness/skills` 是系统级、可验证、可迁移的 skill registry；backend-native skills 只能作为 backend-specific 能力处理，不能默认跨 backend 共享。

### 5.2 统一 Runtime 接口

当前源码新增：

```text
vulnversion/agent_harness/
  __init__.py
  base.py
  task.py
  result.py
  service.py
  json_utils.py
  trace.py
  config.py

  runtimes/
    opencode_runtime.py
    codex_runtime.py
    claude_runtime.py
    replay_runtime.py

  prompts/
    renderer.py
    templates/

  memory/
    schema.py
    manager.py
    retrieval.py
    updates.py

  skills/
    selector.py
    schema.py
    stage1_chunk/
    stage2_rci/
    stage3_verify/
```

接口语义：

```python
class AgentRuntime:
  def create_readonly_session(self, title: str) -> str: ...

  def run_json(
    self,
    *,
    session_id: str,
    prompt: str,
    system: str | None = None,
    timeout_s: float | None = None,
    tools: dict[str, bool] | None = None,
    metadata: dict | None = None,
  ) -> dict: ...

  def capabilities(self) -> AgentCapabilities: ...
```

`AgentCapabilities` 至少包括：

```python
class AgentCapabilities:
  backend: str
  supports_bash: bool
  supports_git_tools: bool
  supports_skills: bool
  supports_readonly_permissions: bool
  supports_system_prompt: bool
  supports_session_reuse: bool
  max_context_tokens: int | None
  json_reliability: str
```

当前实现边界：

1. `OpenCodeRuntime` 是唯一可执行 runtime，内部复用现有 `OpenCodeAgent` / `OpenCodeClient`。
2. `CodexRuntime`、`ClaudeRuntime` 只作为预留类存在，不能在当前实验中声明为已接入。
3. `ReplayRuntime` 只保留接口占位，后续必须基于 trace artifact 实现。
4. Stage1/2/3 只依赖 `AgentRuntime` 协议，不再直接依赖 `OpenCodeAgent` 类型。
5. 当前 prompt 仍由原 Python prompt builder 生成，`agent_harness/prompts/templates` 只作为后续 prompt migration 占位。

### 5.2.1 Backend-specific Skills Boundary

Skill 必须区分三类：

| Skill 类型 | 位置 | 谁会加载 | 是否可跨 backend |
|---|---|---|---|
| OpenCode native skill | `VulnVersion/.opencode/skills` | 只有 OpenCode server / OpenCode agent | 否 |
| VulnVersion harness skill | `vulnversion/agent_harness/skills` | VulnVersion 自己的 selector / prompt renderer | 可以，但必须 verifier-gated |
| Codex / Claude native skill | 各自 CLI/SDK/plugin/skill 机制 | 对应 backend | 否，除非显式转换 |

因此当前阶段不能假设 Codex/Claude 会直接复用 `.opencode/skills`。后续如果要做 backend 公平对比，应采用两层策略：

1. **backend-native skill adapter**：只描述该 backend 可以加载哪些原生 skill、如何加载、是否启用。
2. **VulnVersion canonical skill registry**：将经过验证的 stage skill 用 backend-neutral Markdown/JSON 表示，再由各 backend adapter 转换为对应注入格式。

当前源码阶段仅启用 OpenCode native skills，并保留 `agent_harness/skills` 作为未来 canonical skill registry 的脚手架。

### 5.2.2 OpenCode Adapter Artifacts

当前 OpenCode-first 阶段先不引入 Codex/Claude，也不依赖真实 CVE 全链路 smoke run。OpenCode adapter 需要先稳定以下可审计 artifacts：

| Artifact | 位置 | 内容 | 用途 |
|---|---|---|---|
| `agent_runtime.json` | 每个 CVE `Result/<repo>/<cve>/` | backend、capabilities、OpenCode health、provider/model、native skills、native tools、readonly permission rules、known sessions | 复现实验环境，确认 `.opencode/skills` 是否被 OpenCode backend 看到 |
| `agent_trace.jsonl` | 每个 CVE `Result/<repo>/<cve>/` | 每次 `run_json` 的 stage、task_type、trace_id、prompt/system hash、latency、parsed_keys、error | 后续 ReplayRuntime、failure attribution、memory/self-evolution 的最小事实源 |
| `agent_sessions.json` | 每个 CVE `Result/<repo>/<cve>/` | `AgentService` 已知 session 列表、role、messages_count | 审计 Stage1/2 split session 与 Stage3 per-tag session |
| `opencode_messages_all.jsonl` | 每个 CVE `Result/<repo>/<cve>/` | 所有已知 OpenCode session 的原始 messages | 保留 backend-native 原始轨迹，供离线失败分析使用 |
| `opencode_messages.json/jsonl` | 每个 CVE `Result/<repo>/<cve>/` | 主 session 的兼容格式 messages | 兼容旧版 `Result` 分析脚本 |

OpenCode adapter 的 scope 是 backend-specific。它可以记录 tool crash、JSON repair、session policy、native skill inventory 等后端行为，但这些内容不能被提升为漏洞语义证据。

### 5.2.2.1 OpenCode-native Skills Audit

当前只兼容 OpenCode 路径，因此 `.opencode/skills` 先作为 backend-specific 能力审计和优化，而不是 VulnVersion canonical skills。新增静态检查脚本：

```text
VulnVersion/tests/check_opencode_skills.py
```

该检查只做 local/static audit，不调用 OpenCode，不读取全部 CWE 大文件：

1. 检查 `.opencode/skills/git-navigation/SKILL.md` 和 references 是否完整。
2. 检查 git-navigation 是否包含 judge-only、`tag:path` snapshot、`git grep` / `git show` evidence discipline、failure-triggered workflow 等 OpenCode v2 关键约束。
3. 检查 `.opencode/skills/cwe-skills/SKILL.md` 和 `references/index.json` 是否存在。
4. 只从当前数据集文件中精确提取出现过的 CWE-ID，并检查对应 `references/by-id/CWE-XXX/{meta.json,stage1.md,stage2.md,stage3.md}`。
5. 数据集 CWE static base 缺失先作为 coverage warning，不阻塞 learned overlay 和 harness 地基。

当前 audit 的用途是确认 OpenCode backend 能看到哪些 native skills，并确认 native skills 没有越过 judge-only 边界。它不是 canonical skill verifier，也不能证明 skill 有效果。

### 5.2.2.2 git-navigation v2 Design

`git-navigation` v2 是 OpenCode-native skill，目标是服务 VulnVersion 的三阶段判别，而不是做版本范围规划：

| Stage | 允许的能力 | 禁止的能力 |
|---|---|---|
| Stage1 | chunk relevance / chunk role 判别 | 生成 RCI、推断 affected range |
| Stage2 | root cause、predicate、guard 证据构造 | tag plan、scan order、early stop、affected range |
| Stage3 | planner 给定 tag 的单 tag verdict | 选择 tag、利用 neighbor verdict、聚合范围 |

Stage3 tag snapshot 规则必须优先执行：

1. 判断 tag 时必须读取 `tag:path` 或等价 tag snapshot。
2. 不能用工作区文件替代当前 tag 的源码。
3. 路径不存在时，先做 rename / move / topology 检查，再决定是否证据不足。
4. `git grep` 只能定位候选位置，不能单独作为 verdict evidence。
5. 最终 verdict 需要 `git show` 或等价上下文证据支撑。
6. 当前 tag 的代码证据优先级高于 commit message、advisory 和 CWE 先验。

failure-triggered workflow 只处理导航和证据判别风险：path missing、generic token overmatch、fix-token overmatch、rename/move ambiguity、weak negative evidence。任何 workflow 都不得写入 GT affected tags、affected range、neighbor verdict 或 planner state。

### 5.2.2.3 CWE Skills Static Base and Learned Overlay

`cwe-skills` 的 `references/by-id` 来自 CWE 官网脚本生成，定位是 static base knowledge。它可以重建，不应被 self-evolution 直接覆盖。

自学习、自进化只写入 learned overlay：

```text
.opencode/skills/cwe-skills/references/learned/
  README.md
  by-id/
    .gitkeep
  candidates/
    .gitkeep
```

learned overlay 的准入规则：

1. candidate overlay 只能来自 case pack、ReplayRuntime gate、小样本 OpenCode 验证和 leakage gate。
2. candidate overlay 默认不可被 skill router 注入。
3. verified overlay 才允许被 OpenCode native skill router 读取。
4. learned overlay 不能包含 GT affected tags、affected range、neighbor verdict、planner state、tag plan、scan order 或 early stop。
5. 如果 learned rule 可以 deterministic Python 实现，应晋升为 ArtifactMemory，而不是长期保存在 CWE skill。

### 5.2.3 Prompt Provenance v0

在迁移 prompt template 之前，先将当前 Python prompt builder 登记为可追踪的 v0 prompt。这样可以在不改变 prompt 内容的前提下，获得 prompt A/B、ReplayRuntime 和 failure attribution 所需的 provenance。

当前 v0 prompt 约定：

| Stage | prompt_name | prompt_version | schema_name | prompt_builder |
|---|---|---|---|---|
| Stage1 | `stage1_chunk` | `v0` | `stage1_chunk_role` | `python` |
| Stage2 | `stage2_rci` | `v0` | `stage2_rci` | `python` |
| Stage3 | `stage3_verdict` | `v0` | `stage3_tag_verdict` | `python` |

`AgentService.run_json()` 必须把 `prompt_name`、`prompt_version`、`schema_name`、`prompt_builder`、`prompt_hash` 写入 `agent_trace.jsonl`。`prompt_hash` 只能说明 prompt 文本是否相同；`prompt_name/version/schema_name` 才能支持跨实验归因。

### 5.2.4 AgentTask Migration Policy

`AgentTask` 是把一次 Agent 判断变成可审计实验单元的中间层。当前地基层已完成 Stage1/Stage2/Stage3 的显式化迁移：所有阶段优先走 `AgentService.run_task()`，direct runtime 仍保留 `run_json()` fallback 以兼容 OpenCode adapter 和后续 backend。

迁移后的阶段边界：

| Stage | task_type | forbidden_context |
|---|---|---|
| Stage1 | `chunk_role` | `tag_plan`, `early_stop`, `gt_affected_tags` |
| Stage2 | `rci_induction` | `tag_plan`, `early_stop`, `gt_affected_tags`, `affected_range` |
| Stage3 | `tag_verdict` | `tag_plan`, `scan_order`, `early_stop`, `gt_affected_tags`, `affected_range`, `neighbor_tag_verdicts` |

所有 `AgentTask` 必须显式记录：

```text
judgement_only = true
forbidden_context = [...]
```

这些字段不是给 Agent 作为漏洞证据使用，而是给 harness、trace、ReplayRuntime 和后续 verifier gate 做边界审计。Stage3 仍不得把 planner state、neighbor tags、GT affected tags 或 affected range 注入 prompt。

### 5.2.5 Harness Mode Config

`agent_harness/config.py` 维护当前 harness 的全局模式。当前默认不启用 memory/skills 注入，只记录可审计模式：

| 字段 | 取值 | 默认值 | 说明 |
|---|---|---|---|
| `memory_mode` | `off`, `read_only`, `write_candidate`, `full` | `off` | 当前只落审计字段，不检索、不注入、不写入 memory |
| `skill_mode` | `off`, `backend_native`, `canonical_verified` | `backend_native` | 当前允许 OpenCode 使用 `.opencode/skills`，但不启用 harness canonical skill 注入 |
| `replay_mode` | `off`, `strict`, `permissive` | `off` | 当前主流程不自动 replay，ReplayRuntime 只用于显式本地回放 |

环境变量：

```text
VV_MEMORY_MODE
VV_SKILL_MODE
VV_REPLAY_MODE
```

`AgentService.runtime_manifest()` 必须记录 `harness_config`，使每个 CVE run 都可复现实验模式。模式字段本身不得改变 prompt，除非后续进入明确的 injection phase 并通过 verifier gate。

### 5.3 Harness 需要记录的 trace

每次 Agent 调用都要记录：

```json
{
  "trace_id": "...",
  "backend": "opencode|claude_code|codex|replay",
  "stage": "stage1|stage2|stage3",
  "cve_id": "...",
  "repo": "...",
  "session_id": "...",
  "prompt_name": "...",
  "prompt_version": "...",
  "schema_name": "...",
  "prompt_hash": "...",
  "system_hash": "...",
  "parsed_output_path": "...",
  "prompt_path": "...",
  "system_path": "...",
  "timeout_s": 0,
  "latency_s": 0,
  "error": null,
  "metadata": {
    "memory_mode": "off",
    "skill_mode": "backend_native",
    "replay_mode": "off",
    "retrieved_memory_ids": [],
    "selected_skills": [],
    "suppressed_skills": [],
    "injection_policy": "off"
  }
}
```

该 trace 是后续 memory、自学习、backend 对比实验和 artifact evaluation 的基础。

### 5.3.1 Trace-linked Parsed Output Artifacts

每次 `AgentService.run_json()` 调用都要在当前 run 的输出目录下维护调用级 artifact：

```text
agent_calls/
  <trace_id>.parsed.json
  <trace_id>.prompt.txt
  <trace_id>.system.txt
  index.jsonl
```

规则：

1. `parsed.json` 保存解析后的 JSON object，不保存 raw model output。
2. `prompt.txt` 保存本次 prompt 文本，用于 prompt hash 复核和 replay 匹配。
3. `system.txt` 仅在 system prompt 非空时写入。
4. `index.jsonl` 记录 `trace_id`、stage、task_type、prompt provenance、prompt_hash、system_hash、artifact path 和 metadata。
5. artifact 写入失败不得影响 Agent 主流程，只能在 trace metadata 中记录 `artifact_write_error`。
6. 非 CVE harness probe 也应写入 `Result/_agent_harness_smoke/agent_calls/`。

这些 artifact 是 ReplayRuntime、failure attribution、prompt A/B 和 memory/self-evolution 的事实源。它们不等于 memory，也不会自动注入后续 prompt。

### 5.3.2 Injection Audit Stub

当前地基层只记录注入审计字段，不真正注入 memory 或 canonical skills。`AgentService.run_json()` metadata 默认加入：

```json
{
  "memory_mode": "off",
  "skill_mode": "backend_native",
  "replay_mode": "off",
  "retrieved_memory_ids": [],
  "selected_skills": [],
  "suppressed_skills": [],
  "injection_policy": "off"
}
```

调用方显式传入同名字段时，以调用方为准。该 stub 的用途是保证后续 memory/skills 注入有固定审计槽位；当前不得改变 prompt，不得检索 memory，不得把 memory hint 当作 verdict evidence。

### 5.3.3 Evidence-first Agent Enhancement Gate

Agent enhancement 必须继承 Step3 的证据优先原则：所有 memory、skills、prompt、自学习、自进化方案，不能只来自论文启发或自顶向下设计。没有真实 case、trace、replay 或小样本验证支撑的方案，只能标记为 `hypothesis`，不能进入默认主路径。

状态定义：

| 状态 | 含义 | 是否可进入主流程 |
|---|---|---|
| `hypothesis` | 只有想法、论文启发、人工判断或 agent proposal | 否 |
| `case_backed_candidate` | 至少有真实 case pack 支撑，但尚未通过 replay / 小样本验证 | 只能实验开关启用 |
| `accepted` | 通过 case pack、ReplayRuntime 回放和小样本验证，且无不可接受回归 | 可以进入默认路径 |

新增 `agent_enhance_cases/` 作为所有 agent enhancement 的 case pack 根目录。推荐位置：

```text
E:\AI\Agent\workflow\VulnVersion\Result_agent_enhance_cases\
  <enhancement_id>/
    case_index.jsonl
    hypothesis.md
    replay_summary.json
    small_sample_summary.json
    regression_cases.jsonl
    improved_cases.jsonl
    cases/
      <repo>__<cve_id>__<case_id>/
        source_manifest.json
        before.agent_trace.jsonl
        before.agent_calls_index.jsonl
        before.rci.json
        before.per_tag_verdict.jsonl
        before.eval.json
        failure_analysis.md
        candidate_memory_or_skill.json
        replay_result.json
        small_sample_result.json
```

`case_index.jsonl` 每行至少包含：

```json
{
  "case_id": "...",
  "enhancement_id": "...",
  "status": "hypothesis|case_backed_candidate|accepted|rejected",
  "repo": "...",
  "cve_id": "...",
  "stage": "stage1|stage2|stage3",
  "failure_type": "fp|fn|unknown|timeout|json_error|anchor_relocation_failure|predicate_overmatch|predicate_undermatch|other",
  "source_artifacts": [
    "agent_trace.jsonl",
    "agent_calls/index.jsonl",
    "rci.json",
    "per_tag_verdict.jsonl",
    "eval.json"
  ],
  "bottom_up_observation": "...",
  "proposed_change": "...",
  "replay_status": "not_run|pass|fail",
  "small_sample_status": "not_run|pass|fail",
  "leakage_check": "pass|fail",
  "regression_risk": "low|medium|high"
}
```

准入规则：

1. 没有 `agent_enhance_cases/<enhancement_id>/case_index.jsonl` 的 enhancement 只能写入 hypothesis backlog。
2. 没有 ReplayRuntime 结果的 memory / skill / prompt change 不能进入 `read_only memory injection`。
3. 没有小样本验证结果的 enhancement 不能进入默认主流程。
4. 只看 aggregate metric 不够，必须同时输出 improved cases、regression cases 和 unchanged failure cases。
5. case pack 中可以使用 GT 作为离线 oracle signal，但 GT affected tags、affected range、neighbor verdict 不得进入 prompt、memory content 或 skill content。

### 5.4 ReplayRuntime

必须实现 ReplayRuntime，用于：

1. 无 API 复现实验。
2. 回放历史 Agent 输出进行 regression test。
3. 比较 prompt/memory/skill 改动前后的行为差异。
4. 作为论文 artifact 的稳定运行模式。

ReplayRuntime 不重新调用模型，只读取历史 trace 中的 parsed output。

当前源码阶段实现 ReplayRuntime v1 的最小可用本地回放。它从 `agent_calls/index.jsonl` 读取 parsed output artifact，不调用 OpenCode/Codex/Claude。v1 匹配契约为：

```text
source_format: agent_calls/index.jsonl
match_fields:
  - stage
  - task_type
  - prompt_name
  - prompt_version
  - schema_name
  - prompt_hash
required_future_fields:
  - trace_id
  - parsed_output_path
```

ReplayRuntime v1 行为：

1. 支持从 `trace_path` 或 `calls_index_path` 初始化。
2. 命中后读取 `parsed_output_path` 并返回 parsed JSON。
3. 未命中抛出 `ReplayMissError`，错误信息必须包含匹配字段。
4. `capabilities.json_reliability = "recorded"`。
5. `diagnostics()` 记录 loaded entries、source path 和 match fields。
6. 当前只能声明为 `local_replay_capable_not_batch_validated`，不能声明为批量实验 backend。

## 6. Memory 体系设计

### 6.0 Memory 与 Skills 的边界

Memory 和 Skills 不能混用。二者的核心差异是：memory 保存“当前或历史任务上下文”，skills 保存“可复用的做事规则”。

| 维度 | Memory | Skills |
|---|---|---|
| 主要作用 | 补全上下文，帮助 Agent 更好理解当前 repo / CVE / tag / line | 提供可复用、可触发、可验证的判断流程或操作规则 |
| 内容粒度 | 事实、证据、路径别名、失败案例、RCI 可靠性、line 风险 | compact procedure、decision checklist、repair rule、search strategy |
| 作用域 | 常常是 repo-specific、CVE-specific、line-specific、tag-specific | 通常至少 stage-specific，经过验证后可提升到 CWE/repo/global |
| 生命周期 | candidate -> verified -> deprecated / promoted | candidate -> active -> verified -> promoted_to_artifact |
| 注入语义 | “context hint / navigation hint / risk hint”，不是 verdict evidence | “how to judge / how to search / how to avoid known mistakes” |
| 复用要求 | 可只对单 CVE 或单 repo 有用 | 必须能跨多个 case 复用，且有 replay / 小样本验证支撑 |

判断标准：

1. 如果内容回答的是“这个 CVE / repo / tag 有什么上下文”，优先设计为 memory。
2. 如果内容回答的是“遇到这类问题应按什么步骤判断”，才值得设计为 skill。
3. 如果内容只对一个 CVE 的某个 tag 成立，禁止设计为 skill。
4. 如果内容包含具体 affected tags、GT、neighbor verdict、affected range，既不能成为 skill，也不能作为 verdict evidence 注入。
5. 如果多个 case pack 证明某条 memory 中的流程具有跨 case 复用价值，可以通过 verifier gate 晋升为 SkillMemory。

示例：

| 内容 | 应放位置 | 原因 |
|---|---|---|
| `openssl` 的某历史分支把路径 `crypto/x509` 移到另一路径 | RepoMemory | repo path context，用于导航 |
| 某 CVE 的 RCI 中 `token X` 在旧版本文件名不同但语义相同 | CVE/Line Memory | 补全当前 CVE 的跨版本上下文 |
| “NOT_AFFECTED 必须有 localized fix / feature absence / guard invalidation 三类证据之一” | Stage3 Skill | 可跨 case 复用的判定规则 |
| “repo-wide grep 单独命中不能证明 affected” | Stage3/CWE Skill | 可复用 evidence adjudication rule |
| 某个 tag 的 verdict 或邻近 tag 的 A/N 结果 | Tag Evidence / Trace only | 只能审计，不可晋升为 skill，不可作为当前 tag 证据 |

### 6.1 Memory 类型

VulnVersion 不使用单一向量库作为 memory。Memory 按任务语义分型。

| Memory 类型 | 作用 | 来源 | 注入位置 |
|---|---|---|---|
| WorkingMemory | 当前 CVE / 当前 tag / 当前 release line 的短期状态 | runtime | Stage1/2/3 |
| EvidenceMemory | git show/grep/diff 得到的证据事实 | prefetch、Agent evidence | Stage1/2/3 |
| RepoMemory | repo 的目录结构、tag 风格、路径迁移、函数别名 | 多 CVE 累积 | Stage2/3 |
| RCIMemory | RCI 模板、predicate 可靠性、guard 风险 | Stage2 输出、自检、Stage3 反馈 | Stage2 |
| LineMemory | release line 边界、confirmed paths、frontier risk | Stage3 扫描过程 | Stage3 |
| FailureMemory | FP/FN/UNK/TIMEOUT/AGENT_ERROR 的归因 | eval + verdict + trace | self-evolution |
| ProceduralMemory | 可复用验证流程，包含抽象步骤和具体案例 | success/failure trajectories | Stage1/2/3 |
| SkillMemory | 验证通过、可注入 prompt 的 compact skill | promoted procedural memory | Agent prompt |
| ArtifactMemory | 可执行规则、repo adapter、predicate repair policy | promoted skill / rule mining | deterministic layer |

### 6.2 通用 Memory Schema

所有 memory entry 使用统一 envelope：

```json
{
  "memory_id": "...",
  "memory_type": "repo|rci|line|evidence|failure|procedural|skill|artifact",
  "scope": {
    "repo": "...",
    "cve_id": "...",
    "cwe": [],
    "stage": "stage1|stage2|stage3|global",
    "tag": null,
    "line": null,
    "backend": "opencode|claude_code|codex|replay"
  },
  "content": {},
  "evidence": [
    {
      "ref": "...",
      "source": "git_show|git_grep|git_diff|agent_trace|eval|rci_self_check",
      "snippet_hash": "...",
      "snippet": "..."
    }
  ],
  "reliability": {
    "confidence": 0.0,
    "evidence_backed": true,
    "verified": false,
    "promoted": false,
    "failure_count": 0,
    "success_count": 0
  },
  "lifecycle": {
    "status": "candidate|active|deprecated|rejected",
    "created_at_run": "...",
    "updated_at_run": "...",
    "version": 1
  }
}
```

### 6.3 EvidenceMemory

EvidenceMemory 只保存可验证事实，不能保存 Agent 猜测。

示例：

```json
{
  "memory_type": "evidence",
  "content": {
    "tag": "curl-7_66_0",
    "path": "lib/url.c",
    "function": "override_login",
    "predicate_id": "fp1",
    "predicate_status": "matched",
    "localized": true
  }
}
```

用途：

1. 减少 Stage3 重复 git navigation。
2. 支撑 verdict 的证据回放。
3. 为 FailureMemory 提供事实依据。

### 6.4 RepoMemory

RepoMemory 用于解决跨版本结构变化。

记录内容：

1. tag 命名和 release line 解析规则。
2. 文件路径迁移。
3. 函数重命名或迁移。
4. 常见源码目录。
5. 测试目录、文档目录、无关路径过滤规则。

示例：

```json
{
  "memory_type": "repo",
  "content": {
    "repo": "curl",
    "fact_type": "path_alias",
    "old_path": "lib/url.c",
    "new_path": "lib/urlapi.c",
    "evidence_tags": ["curl-7_61_0", "curl-7_62_0"],
    "confidence": 0.92
  }
}
```

### 6.5 RCIMemory

RCIMemory 负责改进 Step2 的 root cause 和 RCI 生成。

记录内容：

1. 高质量 RCI 模板。
2. 某类 CWE 的强 predicate pattern。
3. 容易造成误判的 weak signals。
4. guard 的适用条件和失效条件。
5. predicate scope 的约束经验。

示例：

```json
{
  "memory_type": "rci",
  "content": {
    "cwe": "CWE-787",
    "failure_mode": "generic_fix_token_overmatch",
    "repair": "fix_predicate must be localized to the vulnerable call site or relocated equivalent",
    "applies_to": ["token_all", "ordered_tokens"]
  }
}
```

### 6.6 LineMemory

LineMemory 是当前 `_hybrid_anchor_relocation` 和 `line_discoveries` 的强化版。

记录内容：

1. confirmed paths。
2. absent paths。
3. line-local first fixed tag。
4. frontier status。
5. non-monotone risk。
6. boundary probe verdicts。

LineMemory 不应该永久无条件复用，默认作用域是同一 CVE 的同一 release line。只有经过多 CVE 验证后，才能晋升为 RepoMemory。

### 6.7 FailureMemory

FailureMemory 是自进化的核心。

错误类型：

| error_type | 说明 |
|---|---|
| false_positive | 非受影响 tag 被判为 AFFECTED |
| false_negative | 受影响 tag 被判为 NOT_AFFECTED |
| unknown_or_parse | verdict 缺失、JSON 失败、字段不合法 |
| timeout_navigation | Agent 导航超时 |
| anchor_missing_error | anchor 路径缺失后搜索不足 |
| predicate_overmatch | predicate 命中无关上下文 |
| predicate_undermatch | 等价漏洞实现未被识别 |
| guard_misfire | guard 过强或过弱 |
| boundary_violation | ASBS 或 release line 假设被破坏 |
| backend_tool_error | Agent harness/tool 层错误 |

FailureMemory 示例：

```json
{
  "memory_type": "failure",
  "content": {
    "error_type": "false_positive",
    "root_cause": "fix_predicate_overmatched_generic_token",
    "symptom": "Agent treated a header macro occurrence as fixed implementation evidence",
    "repair_hint": "Require fix predicate evidence inside anchor function or confirmed relocated equivalent",
    "affected_stage": "stage3"
  }
}
```

### 6.8 ProceduralMemory

ProceduralMemory 保存“如何执行类似验证”的过程知识。

每条 procedural memory 包含：

1. trigger。
2. abstract procedure。
3. concrete supporting cases。
4. known failure modes。
5. confidence and verification status。

示例：

```json
{
  "memory_type": "procedural",
  "content": {
    "name": "localized_fix_predicate_verification",
    "trigger": {
      "stage": "stage3",
      "predicate_kind": ["token_all", "ordered_tokens"],
      "risk_flags": ["generic_fix_token"]
    },
    "procedure": [
      "Locate the anchor function or relocated equivalent first.",
      "Check whether the fix structure appears in that localized implementation.",
      "Ignore header-only, test-only, changelog-only, or unrelated helper occurrences.",
      "Do not output NOT_AFFECTED unless the fix blocks the stated root cause."
    ],
    "supporting_cases": ["..."]
  }
}
```

### 6.9 SkillMemory

SkillMemory 是从 ProceduralMemory 晋升而来的 prompt-level instruction。Skill 必须短、聚焦、可触发、可验证。

Skill 不直接保存 CVE 答案，不允许包含 ground truth affected tag 列表。

### 6.10 ArtifactMemory

ArtifactMemory 是最高等级的 memory。它不只是自然语言，而是可执行或半可执行规则。

候选 artifact：

```text
repo_adapters/<repo>.json
predicate_repair_rules.json
anchor_relocation_policy.json
stage1_chunk_role_rules.json
stage2_rci_templates.json
stage3_verdict_calibration.json
```

Artifact 必须经过 replay / validation CVE 验证后才能启用。

### 6.11 Memory Candidate Store v0

当前源码阶段不直接启用 memory injection，而是先从 case pack 生成离线候选：

```text
VulnVersion/vulnversion/self_evolve/
  memory_candidates.py
  memory_store.py

VulnVersion/tests/build_memory_candidates.py
```

输入：

```text
Result_agent_enhance_cases/<enhancement_id>/case_index.jsonl
```

输出：

```text
Result_agent_enhance_memory/<enhancement_id>/
  memory_candidates.jsonl
  memory_summary.json
```

v0 candidate 类型：

| Type | 来源 | 允许内容 | 禁止内容 |
|---|---|---|---|
| FailureMemory | FP/FN/UNKNOWN/TIMEOUT/JSON_ERROR/AGENT_ERROR | failure type、stage、case source、归因摘要 | GT affected tags、affected range |
| RepoMemory | 多 case repo pattern | repo/tag/path/rename 风格 | CVE 答案、当前 tag verdict |
| RCIMemory | RCI predicates / guards 风险 | predicate/guard 可靠性风险 | affected range、planner state |
| SkillMemory | 重复 case 模式 | 可复用 rule candidate | 单 case rule、未验证 procedure |

每条 candidate 必须保持：

```json
{
  "status": "candidate",
  "injection_allowed": false,
  "promotion_requirements": ["case_pack", "replay_summary", "small_sample_summary", "leakage_gate", "improved_regression_unchanged_report"]
}
```

v0 默认不调用模型，不使用 subagent 总结全量日志。subagent 只能在后续作为人工审计辅助，不能替代 deterministic candidate builder 和 gate。

### 6.12 Leakage and Promotion Gates

新增 blocking gates：

```text
VulnVersion/vulnversion/self_evolve/leakage_gate.py
VulnVersion/vulnversion/self_evolve/promotion_gate.py
VulnVersion/tests/check_memory_candidates.py
```

`leakage_gate.py` 检查 memory candidate 的 `content` 是否包含禁止内容：

```text
gt_affected_tags
ground truth
affected range
neighbor verdict
scan order
early stop
tag plan
planner state
oracle_label
```

`promotion_gate.py` 的最小晋升条件：

1. 有 case pack。
2. 有 `replay_summary.json` 且 status 不是 `not_run`。
3. 有 `small_sample_summary.json` 且 status 不是 `not_run`。
4. 有 `improved_cases.jsonl`、`regression_cases.jsonl`、`unchanged_failure_cases.jsonl`。
5. leakage gate pass。
6. `SkillMemory` 至少来自重复 case 模式。

gate 输出：

```text
gated_memory_candidates.jsonl
gate_summary.json
```

当前真实 case pack 的默认结果必须是 blocked；只有 fixture 或后续经过 replay + 小样本 OpenCode 验证的 enhancement，才允许出现 `status=verified`。gate 只更新 candidate status，不改变主流程 prompt，不启用 memory 注入。

## 7. Memory Dynamics

### 7.1 Formation

Memory 形成来源：

| 来源 | 形成的 memory |
|---|---|
| Stage1 chunk annotation | chunk role memory、weak chunk pattern |
| Stage2 RCI output | RCI memory、predicate memory、guard memory |
| Stage2 self-check | RCI reliability memory |
| Stage3 prefetch | evidence memory |
| Stage3 verdict | line memory、procedural memory |
| eval.json | failure memory |
| opencode/agent traces | trace memory、harness memory |

### 7.2 Retrieval

Memory retrieval 必须分阶段：

| 阶段 | 检索 key | 检索 memory |
|---|---|---|
| Step1 | repo, CWE, file extension, diff pattern | chunk role procedural memory |
| Step2 | CWE, patch role, root cause tokens, repo | RCI memory, repo memory |
| Step3 | repo, CVE, tag, release line, predicates, paths | evidence, line, repo, procedural, skill memory |

检索策略：

1. 先精确过滤 scope，再做 semantic retrieval。
2. 高风险 memory 必须低优先级注入。
3. 同一 prompt 中注入 memory 数量必须有限，避免 SkillsBench 中的 context burden。
4. 与当前 evidence 冲突的 memory 不注入，只记录 conflict。

### 7.3 Update

Memory update 不采用简单 append。需要 memory operation skills。

基础操作：

| 操作 | 说明 |
|---|---|
| INSERT | 新事实、新失败、新过程 |
| UPDATE | 修正已有 memory |
| MERGE | 合并重复 memory |
| DELETE | 删除错误或过时 memory |
| DEPRECATE | 降权但保留审计 |
| PROMOTE | 晋升为 skill 或 artifact |
| SUPPRESS | 当前任务检索到但不注入 |

### 7.4 Forgetting

需要明确废弃机制：

1. 多次导致 FP/FN 的 memory 降权。
2. 只在单个 CVE 成立、跨 CVE 失败的 memory 限定作用域。
3. 与新 evidence 冲突的 memory 标记 stale。
4. backend-specific failure 不晋升为 general skill。

## 8. Memory Operation Skills

Memory skills 不是 Agent task skills，而是用于决定如何形成、修改和晋升 memory 的策略。

### 8.1 初始 Memory Skills

```text
INSERT_EVIDENCE_FACT
UPDATE_REPO_PATH_ALIAS
INSERT_FAILURE_CASE
UPDATE_PREDICATE_RELIABILITY
PROMOTE_PROCEDURE_TO_SKILL
SUPPRESS_UNVERIFIED_MEMORY
DEPRECATE_HARMFUL_MEMORY
COMPILE_SKILL_TO_ARTIFACT
```

### 8.2 Controller

Memory controller 输入：

```json
{
  "stage": "stage1|stage2|stage3",
  "current_output": {},
  "retrieved_memory": [],
  "eval_signal": {},
  "hard_case": {},
  "backend": "..."
}
```

输出：

```json
{
  "selected_memory_skills": ["INSERT_FAILURE_CASE", "UPDATE_PREDICATE_RELIABILITY"],
  "reason": "...",
  "expected_effect": "reduce false positives caused by generic fix tokens"
}
```

### 8.3 Designer

Designer 周期性读取 hard cases，执行：

1. 聚类 hard cases。
2. 找出重复 failure mode。
3. 判断是否已有 memory skill 覆盖。
4. 修改旧 memory skill 或提出新 memory skill。
5. 交给 verifier gate 验证。

## 9. Stage-Specific Self-Evolving Skill Systems

VulnVersion 不能只维护一套通用 skills。Step1、Step2、Step3 的 Agent 任务、输入证据、输出 schema、错误模式和评估信号完全不同，因此必须维护三套独立但可协同进化的 SkillBank。

```text
vulnversion/skills/
  stage1_chunk/
    SKILL_INDEX.json
    classify_primary_fix.md
    distinguish_refactor_from_fix.md
    identify_supporting_fix.md
    ignore_test_doc_changelog.md
    detect_multi_file_fix_dependency.md

  stage2_rci/
    SKILL_INDEX.json
    derive_root_cause_theorem.md
    design_discriminative_predicates.md
    construct_cross_version_anchor.md
    separate_weak_signals.md
    encode_guard_conditions.md
    model_backport_and_nonmonotone_risk.md

  stage3_verify/
    SKILL_INDEX.json
    rename_aware_anchor_search.md
    localized_predicate_matching.md
    conservative_not_affected.md
    resolve_evidence_conflict.md
    handle_backport_nonmonotone_line.md
    calibrate_low_confidence_verdict.md
```

每个 stage skill 必须有明确 trigger、输入字段、输出影响、适用范围、禁用条件、证据要求和历史 hard case 支撑。未经验证的 skill 只能作为 candidate，不允许直接进入主流程 prompt。

### 9.1 Skill Package Schema

每个 skill 文件建议使用统一 front matter + 正文结构：

```yaml
skill_id: stage3.localized_predicate_matching
stage: stage3
version: 1
status: candidate|active|verified|deprecated
owner_component: stage3_verify
trigger:
  cwe: ["*"]
  predicate_kind: ["token_all", "ordered_tokens", "regex"]
  risk_flags: ["generic_token", "header_macro", "repo_wide_match"]
inputs:
  - rci.anchor
  - rci.vuln_predicates
  - rci.fix_predicates
  - prefetched.files
  - prefetched.grep
outputs_influenced:
  - predicate_evaluations
  - verdict
forbidden_use:
  - infer verdict from GT affected tags
  - treat memory as current-tag evidence
verification:
  gates: ["schema", "evidence", "leakage", "replay", "validation"]
metrics:
  target: "reduce false NOT_AFFECTED caused by generic fix-token matches"
```

正文包含：

```text
Purpose
When to use
Procedure
Evidence requirements
Failure modes prevented
Examples from accepted memories
Do-not-use cases
Change log
```

### 9.2 Skill Lifecycle

Skill 的生命周期：

```text
candidate
  -> active
  -> verified
  -> promoted_to_artifact
  -> deprecated
```

状态含义：

| 状态 | 含义 | 是否可注入主 Agent |
|---|---|---|
| candidate | 从 memory / hard case 生成，未验证 | 否 |
| active | 通过 schema/evidence/leakage gate，小规模试用 | 仅实验模式 |
| verified | 通过 replay/validation gate | 是 |
| promoted_to_artifact | 已编译为 deterministic rule 或 adapter | 不再作为主要 prompt skill |
| deprecated | 导致退化或过时 | 否 |

### 9.3 Stage1 SkillBank：Vuln Chunk Recognition Skills

Stage1 skills 面向 patch chunk role 分类。它们不负责生成 root cause，也不负责版本影响判定。

#### 8.3.1 Stage1 Core Skills

| skill_id | 目标 | 触发条件 | 防止的错误 |
|---|---|---|---|
| `stage1.classify_primary_fix` | 识别直接阻断漏洞机制的 chunk | diff 修改校验、边界、权限、状态机、编码、释放逻辑 | 漏掉真正修复 chunk |
| `stage1.identify_supporting_fix` | 识别使主修复生效的辅助 chunk | API 签名变化、调用链传播、错误码传播、结构体字段配套变化 | 把必要辅助改动丢弃 |
| `stage1.distinguish_refactor_from_fix` | 区分安全修复与重构 | 大规模 rename、formatting、函数抽取、无语义变化 | 重构 chunk 误入 RCI |
| `stage1.ignore_test_doc_changelog` | 排除测试、文档、changelog | path 命中 tests/docs/NEWS/examples | 测试或说明文本污染 root cause |
| `stage1.detect_multi_file_fix_dependency` | 识别跨文件共同构成的修复 | 多文件 patch、同一符号跨文件传播 | 只保留单个 chunk 导致 RCI 不完整 |

#### 8.3.2 Stage1 Skill 输入

```json
{
  "cve_id": "...",
  "cwe": [],
  "cve_desc": "...",
  "chunk": {
    "file_path": "...",
    "hunk_header": "...",
    "removed_lines": [],
    "added_lines": []
  },
  "repo_memory": {},
  "failure_memory": [],
  "historical_negative_examples": []
}
```

#### 8.3.3 Stage1 Skill 输出影响

Stage1 skills 不直接改变最终 verdict，只影响：

1. chunk role。
2. `rci_relevant_chunks`。
3. `excluded_chunks`。
4. Step2 的 patch_semantics 输入质量。

#### 8.3.4 Stage1 Skill 自进化信号

Stage1 skill 从以下 hard cases 中进化：

1. Step2 生成的 RCI 缺少关键 root cause，反查发现 Step1 排除了关键 chunk。
2. Stage3 FP/FN 归因到 RCI predicate 过宽/过窄，反查 Step1 输入 chunk 污染或遗漏。
3. 人工审计标记 chunk role 错误。
4. 不同 backend 对同一 chunk role 分歧明显。

Stage1 skill patch 只能修改：

1. role boundary rule。
2. negative examples。
3. path filter。
4. chunk effect taxonomy。

禁止 Stage1 skill 写入具体 CVE affected versions。

#### 8.3.5 Stage1 Skill 验收指标

1. relevant chunk precision。
2. relevant chunk recall。
3. test/doc/refactor false inclusion rate。
4. primary fix false exclusion rate。
5. downstream RCI quality delta。

### 9.4 Stage2 SkillBank：Root Cause and RCI Extraction Skills

Stage2 skills 面向漏洞定理归纳。它们的核心目标是把 patch/CVE/source context 转化为跨版本可验证的 RCI，而不是复述 diff。

#### 8.4.1 Stage2 Core Skills

| skill_id | 目标 | 触发条件 | 防止的错误 |
|---|---|---|---|
| `stage2.derive_root_cause_theorem` | 构造漏洞存在性定理 | 所有 CVE | root cause 过浅，只描述 patch |
| `stage2.design_discriminative_predicates` | 设计强区分 predicate | patch 中有明确 vuln/fix token | predicate 过宽或过窄 |
| `stage2.construct_cross_version_anchor` | 构造跨 tag anchor | 文件/函数可能迁移 | 老版本找不到 anchor |
| `stage2.separate_weak_signals` | 将弱信号移出 predicate | header macro、generic token、test-only token | fix/vuln predicate overmatch |
| `stage2.encode_guard_conditions` | 设计 guards 和禁用条件 | feature gate、alternative implementation、refactor | guard misfire |
| `stage2.model_backport_and_nonmonotone_risk` | 建模 backport 和非单调 release line | 多分支修复、多 fixing commits | 错误启用线性/单调假设 |

#### 8.4.2 Stage2 Skill 输入

```json
{
  "cve_id": "...",
  "cwe": [],
  "cve_desc": "...",
  "patch_semantics": {},
  "fix_commit": "...",
  "vuln_commit": "...",
  "repo_memory": {},
  "rci_memory": [],
  "stage3_feedback_memory": []
}
```

#### 8.4.3 Stage2 Skill 输出影响

Stage2 skills 影响：

1. `root_cause`。
2. `anchor` / `anchor_at_vuln`。
3. `known_renames`。
4. `vuln_predicates`。
5. `fix_predicates`。
6. `guards`。
7. `metadata.risk_flags`。
8. `metadata.preferred_stage3_mode`。

#### 8.4.4 Stage2 Skill 自进化信号

Stage2 skill 从以下 hard cases 中进化：

1. RCI self-check 失败。
2. Stage3 大量 FP，且归因到 predicate overmatch。
3. Stage3 大量 FN，且归因到 predicate undermatch 或 anchor relocation failure。
4. Guard 导致早停或误判。
5. 同类 CWE 的历史 RCI 反复出现相同缺陷。

Stage2 skill patch 优先修改：

1. theorem field 要求。
2. predicate 设计约束。
3. weak signal 分类规则。
4. anchor 设计规则。
5. guard 使用边界。

#### 8.4.5 Stage2 Skill 验收指标

1. RCI self-check pass rate。
2. predicate localization rate。
3. weak signal leakage rate。
4. Stage3 FP/FN delta。
5. anchor relocation success rate。
6. guard misfire rate。

### 9.5 Stage3 SkillBank：Tag-level Verification Skills

Stage3 skills 面向给定 tag 的漏洞存在性判定。它们不负责 tag plan，不负责选择扫描范围，不负责决定 ASBS/early-stop 策略，也不负责利用邻近 tag 直接推断当前 tag。

#### 8.5.1 Stage3 Core Skills

| skill_id | 目标 | 触发条件 | 防止的错误 |
|---|---|---|---|
| `stage3.rename_aware_anchor_search` | anchor missing 时执行重命名/迁移搜索 | anchor file missing、function missing | 过早 NOT_AFFECTED |
| `stage3.localized_predicate_matching` | predicate 必须命中局部实现 | repo-wide grep 命中、generic token | FP/FN from unrelated match |
| `stage3.conservative_not_affected` | 提高 NOT_AFFECTED 证据门槛 | fix evidence 弱、feature absence 不确定 | false negative |
| `stage3.resolve_evidence_conflict` | 处理 prefetch、grep、memory、source 冲突 | evidence_conflicts 非空 | 随机采信单一证据 |
| `stage3.handle_backport_nonmonotone_line` | 在当前 tag 证据混杂时提醒保守裁决 | line risk high、multi-fix commits | 错误把 planner 的单调性假设当成当前 tag 证据 |
| `stage3.calibrate_low_confidence_verdict` | 低置信判定校准 | predicate mixed、tool partial failure | 过度自信 verdict |

#### 8.5.2 Stage3 Skill 输入

```json
{
  "cve_id": "...",
  "tag": "...",
  "line": "...",
  "rci": {},
  "prefetched": {},
  "line_memory": {},
  "repo_memory": {},
  "procedural_memory": [],
  "skill_memory": []
}
```

#### 8.5.3 Stage3 Skill 输出影响

Stage3 skills 影响：

1. anchor relocation order。
2. predicate evaluation。
3. fix evaluation。
4. guard evaluation。
5. evidence conflict handling。
6. final verdict。
7. confidence calibration。

Stage3 skills 不影响：

1. tag plan。
2. release line selection。
3. scan order。
4. ASBS probe selection。
5. early-stop policy。
6. affected range aggregation。

#### 8.5.4 Stage3 Skill 自进化信号

Stage3 skill 从以下 hard cases 中进化：

1. FP：非 affected tag 被判 AFFECTED。
2. FN：affected tag 被判 NOT_AFFECTED。
3. UNK / parse failure。
4. TIMEOUT。
5. AGENT_ERROR。
6. backend disagreement。
7. 低置信正确案例，用于优化 confidence calibration。

Stage3 skill patch 优先修改：

1. evidence priority。
2. localized matching rule。
3. NOT_AFFECTED high-bar policy。
4. rename-aware search procedure。
5. conflict resolution rule。

#### 8.5.5 Stage3 Skill 验收指标

1. FP delta。
2. FN delta。
3. UNK/TIMEOUT delta。
4. evidence localization rate。
5. backend disagreement rate。
6. confidence calibration error。

### 9.6 Stage Skill Controller

每个 step 调用主 Agent 前，Skill Controller 根据当前任务上下文选择少量 verified skills。

输入：

```json
{
  "stage": "stage1|stage2|stage3",
  "repo": "...",
  "cve_id": "...",
  "cwe": [],
  "task_features": {},
  "risk_flags": [],
  "retrieved_memory": [],
  "backend": "..."
}
```

输出：

```json
{
  "selected_skills": [
    {
      "skill_id": "stage3.localized_predicate_matching",
      "version": 3,
      "reason": "fix predicate contains generic macro token and repo-wide grep matches",
      "injection_priority": 1
    }
  ],
  "suppressed_skills": [
    {
      "skill_id": "...",
      "reason": "scope mismatch or not verified"
    }
  ]
}
```

默认注入限制：

| Stage | 默认 top-k | 原因 |
|---|---|---|
| Step1 | 2 | chunk prompt 短，避免干扰 role 判断 |
| Step2 | 3 | RCI 构造复杂，需要 theorem/predicate/anchor skills |
| Step3 | 3 | tag verdict 最容易受过多上下文干扰 |

### 9.7 Stage Skill Self-Evolution Loop

每套 Stage SkillBank 独立进化，但共享 hard case buffer 和 verifier gate。

```text
Stage output / eval signal
  -> hard case attribution
  -> map failure to stage skill
  -> propose skill patch
  -> schema/evidence/leakage gate
  -> replay old cases
  -> validation CVE test
  -> accept as new skill version or reject
```

Skill patch candidate schema：

```json
{
  "target_skill_id": "stage2.design_discriminative_predicates",
  "patch_type": "refine|split|merge|deprecate|new_skill",
  "failure_modes_addressed": [],
  "proposed_change": "...",
  "supporting_hard_cases": [],
  "expected_metric_delta": {},
  "risk": "..."
}
```

### 9.8 Skill Verifier Gate

Stage-specific skill 必须经过以下 gate：

| Gate | 检查内容 |
|---|---|
| skill schema gate | skill metadata、trigger、inputs、outputs 合法 |
| scope gate | skill 是否只作用于指定 stage |
| evidence gate | skill 是否由 hard cases / evidence 支撑 |
| leakage gate | 是否包含 GT affected tag 或具体答案 |
| replay gate | 历史案例回放不破坏 schema |
| validation gate | validation CVE 不退化 |
| cost gate | prompt token、latency、timeout 不显著增加 |
| conflict gate | 是否与 verified skill 冲突 |

### 9.9 Skill 与 Memory / Prompt / Artifact 的关系

```text
FailureMemory
  -> ProceduralMemory
  -> Stage-specific SkillMemory
  -> Prompt Injection
  -> ArtifactMemory
```

规则：

1. Memory 是经验事实和过程记录。
2. Skill 是从 memory 提炼出的可执行流程指导。
3. Prompt 是稳定任务协议和输出契约。
4. Artifact 是经过多轮验证后可确定性执行的策略。
5. Skill 不能取代 current-tag evidence。
6. Skill 不能直接输出 verdict，只能影响 Agent 的调查过程和证据裁决。

## 10. Self-Evolution Loop

### 10.1 离线自进化主循环

```text
Run benchmark batch
  -> collect stage outputs and traces
  -> compute eval and hard cases
  -> attribute failure root cause
  -> form candidate memories
  -> update procedural memory
  -> propose skill/artifact candidates
  -> replay validation CVEs
  -> accept / reject / deprecate
  -> next benchmark batch
```

### 10.2 Hard Case Buffer

Hard case 来源：

1. FP。
2. FN。
3. UNK。
4. TIMEOUT。
5. AGENT_ERROR。
6. 低置信但判定正确。
7. backend disagreement。
8. human override。

Hard case schema：

```json
{
  "case_id": "...",
  "repo": "...",
  "cve_id": "...",
  "tag": "...",
  "stage": "stage1|stage2|stage3",
  "predicted": "...",
  "ground_truth": "...",
  "error_type": "...",
  "agent_backend": "...",
  "rci_snapshot": {},
  "verdict_snapshot": {},
  "trace_refs": [],
  "candidate_root_causes": []
}
```

### 10.3 Verifier Gate

所有 self-evolved 产物必须经过 gate。

Gate 类型：

| Gate | 检查内容 |
|---|---|
| schema gate | JSON/schema 合法 |
| evidence gate | 是否有 git evidence 支撑 |
| leakage gate | 是否泄漏 GT affected tag |
| replay gate | 历史 trace 回放是否稳定 |
| validation gate | validation CVE 上是否提升或不退化 |
| conflict gate | 是否与高置信 memory 冲突 |
| backend gate | 是否只对单一 backend 有效 |

晋升条件：

1. 至少通过 schema/evidence/leakage gate。
2. 对 validation set 无显著退化。
3. 对目标 error type 有可测改善。
4. 不显著增加 timeout 或 JSON parse failure。

## 11. Step1 Agent 增强：Vuln Chunk Recognition

### 11.1 当前责任

Step1 Agent 对 diff chunk 分类：

```text
PRIMARY_FIX
SUPPORTING_FIX
CONTEXTUAL_CHANGE
UNRELATED
```

### 11.2 主要风险

1. 将重构 chunk 误判为漏洞修复。
2. 将测试、文档、格式变更误判为 supporting fix。
3. 忽略跨文件共同构成的漏洞修复。
4. 只看 diff，不看上下文。
5. 不同 backend 对 chunk role 标准不一致。

### 11.3 Memory 增强

Step1 注入：

1. CWE-specific chunk role procedural memory。
2. Repo-specific test/doc path filters。
3. 历史 chunk misclassification failure memory。
4. Backend-specific JSON/output reliability hints。

Step1 产出：

1. chunk role evidence memory。
2. weak chunk pattern memory。
3. chunk classification hard cases。

### 11.4 Skill 增强

候选 skills：

```text
distinguish_security_fix_from_refactor
identify_supporting_fix_chunk
ignore_test_only_or_changelog_chunk
detect_multi_file_fix_dependency
```

### 11.5 自进化指标

1. relevant chunk precision。
2. relevant chunk recall。
3. Stage2 RCI quality downstream impact。
4. excluded chunk false exclusion rate。
5. evidence refs localization rate。

## 12. Step2 Agent 增强：Root Cause / RCI Extraction

### 12.1 当前责任

Step2 Agent 生成：

1. root cause。
2. anchor。
3. anchor_at_vuln。
4. known_renames。
5. vuln_predicates。
6. fix_predicates。
7. guards。
8. trigger_conditions。
9. metadata risk flags。

### 12.2 主要风险

1. root cause 过浅，只复述 patch。
2. predicate 过宽，导致 Stage3 FP。
3. predicate 过窄，导致 Stage3 FN。
4. fix predicate 使用 generic token。
5. guard 过强导致误判 NOT_AFFECTED。
6. anchor 只适配 fix commit，不适配历史 tag。
7. 忽略 backport 和非单调 release line。

### 12.3 Memory 增强

Step2 注入：

1. RCI template memory。
2. CWE root cause procedural memory。
3. Predicate reliability memory。
4. Repo path alias / function alias memory。
5. Stage3 feedback memory。

Step2 产出：

1. RCI memory。
2. predicate memory。
3. guard memory。
4. root cause memory。
5. self-check memory。

### 12.4 Skill 增强

候选 skills：

```text
derive_discriminative_predicates
localize_fix_predicates_to_root_cause
construct_cross_version_anchors
separate_weak_signal_from_predicate
encode_backport_and_nonmonotone_risk
```

### 12.5 Artifact 增强

当某些修复规则稳定后，应编译为 artifact：

```text
predicate_scope_checker
weak_signal_detector
anchor_quality_checker
guard_risk_checker
```

这些 artifact 在 Step2 生成后进行 deterministic validation，减少完全依赖 Agent 自评。

## 13. Step3 Agent 增强：Version Impact Confirmation

### 13.1 当前责任

Step3 Agent 只负责给定 tag 的判定：

```text
AFFECTED | NOT_AFFECTED
```

不负责 tag plan，不负责决定扫描哪些 tag，不负责 ASBS probe 选择，不负责 early stop，不负责根据邻近 tag 推断当前 tag。Agent 的输入是一个确定的 tag 和 RCI；Agent 的输出是该 tag 的 evidence-backed verdict。

### 13.1.1 Stage3 Tag Judge Accuracy Floor

当 Step3 planner 提供一个确定 tag 给 Agent 判定时，Agent 的单 tag judge accuracy 必须达到 **95% 以上** 才允许进入默认主路径。该指标是 Stage3 Agent 判别能力的最低准入线，不是最终 CVE-level 指标保证。

评估定义：

1. 评估对象是 Agent 对 planner 给定 tag 的 `AFFECTED | NOT_AFFECTED` 判定。
2. 统计单位必须区分 `probed_tag_verdict`、`fixed_segment_clear`、`inferred`、`agent_error`，不能把 deterministic inference 伪装成 Agent 判定准确率。
3. Accuracy 必须在 case-backed small sample 和 held-out validation CVEs 上分别报告。
4. 低于 95% 时，不允许启用 `memory_mode="read_only"`、verified skill injection 或新的 prompt 版本作为默认主路径。
5. 95% 是最低门槛。由于 Step3 每个 CVE 通常需要多个 tag probes，单 tag 错误会被 interval inference 放大；因此还必须报告 per-CVE exact match、micro precision/recall/F1、agent error rate、timeout rate 和 error amplification。

硬规则：

```text
tag_judge_accuracy >= 0.95
memory_hint != verdict_evidence
planner_state != tag_judge_evidence
inferred_interval != agent_verdict
```

### 13.2 主要风险

1. anchor missing 后过早判定 NOT_AFFECTED。
2. fix token 出现在无关位置导致 false NOT_AFFECTED。
3. vuln predicate 命中无关上下文导致 false AFFECTED。
4. 没有处理文件迁移、函数重命名、feature gating。
5. 对 pre-fetched evidence 过度信任或忽略。
6. 被 release chronology 或 advisory range 诱导。
7. timeout 和 tool crash 导致 verdict 缺失。
8. 被 planner 上下文诱导，把 boundary/ASBS/early-stop 状态当作当前 tag 证据。

### 13.3 Memory 增强

Step3 注入：

1. LineMemory：confirmed paths、frontier risk。
2. RepoMemory：path aliases、function aliases。
3. EvidenceMemory：已验证的 localized evidence。
4. ProceduralMemory：predicate 验证流程。
5. SkillMemory：短规则，约束高风险判断。

Step3 产出：

1. evidence memory。
2. line memory。
3. verdict memory。
4. failure memory。
5. backend harness memory。

### 13.4 Skill 增强

候选 skills：

```text
rename_aware_anchor_search
localized_fix_predicate_verification
localized_vuln_predicate_verification
conservative_negative_verdict
feature_absence_vs_vulnerability_absence
handle_branch_local_backport
evidence_conflict_resolution
```

### 13.5 Harness 增强

Step3 最依赖 Agent harness，需要：

1. per-tag session isolation。
2. read-only permission enforcement。
3. native git prefetch bypass tool crash。
4. trace-level tool call capture。
5. timeout classification。
6. JSON repair logging。
7. backend disagreement logging。

## 14. Prompt 注入策略

### 14.1 注入顺序

Agent prompt 中 context 顺序建议：

```text
System role and strict evidence rules
Current task input
High-confidence stage-specific memory
Pre-fetched deterministic evidence
RCI / predicates / guards
Investigation plan
Decision policy
Output schema
```

### 14.2 注入预算

为了避免 memory/skill 过载：

| 类型 | 默认上限 |
|---|---|
| SkillMemory | 3 条 |
| ProceduralMemory | 2 条 |
| RepoMemory | 5 条 |
| LineMemory | 当前 line 相关全部，但需 compact |
| EvidenceMemory | 只注入当前 tag/path/predicate 相关 |
| FailureMemory | 不直接注入原始失败，只注入已晋升的 procedural rule |

### 14.3 禁止注入

禁止注入：

1. GT affected tag 列表。
2. 未验证 self-generated skill。
3. 与当前 evidence 冲突但未解释的 memory。
4. 其他 CVE 的具体 verdict 作为判定依据。
5. backend-specific workaround 作为漏洞语义规则。
6. tag plan、scan order、ASBS probe policy、early-stop decision 或 affected range aggregation 结果作为 Agent 判定依据。
7. 邻近 tag verdict 作为当前 tag 的直接证据；如果必须提示 release line 风险，只能以 risk hint 形式注入，并明确“不能替代当前 tag 源码证据”。

## 15. 三轮 Prompt 优化方案

当前 Step1/Step2/Step3 的 prompt 仍偏“通用安全研究员指令”，缺少系统化的任务分解、错误防护、memory 调用策略、harness 约束和可实验版本管理。Prompt 优化必须按轮次推进，三轮目标不同，不能一次性堆砌大量规则。

### 15.1 Prompt 优化总原则

1. Prompt 是 VulnVersion 的实验资产，必须版本化、可回放、可消融。
2. 每个 step 的 prompt 必须明确 Agent 的职责边界。
3. 当前 git evidence 优先于 memory、skill、历史经验和 CVE advisory。
4. Prompt 必须把安全语义拆成可检查对象：source、sink、sanitizer、guard、state transition、trigger condition、fix mechanism。
5. Prompt 必须约束输出 schema，禁止自由叙述污染下游。
6. Prompt 必须支持 backend 对比，不能依赖 OpenCode 独有表达。
7. Prompt 优化必须从 hard cases 反推，而不是只靠人工主观改写。

建议将 prompt 从 Python 代码内联字符串逐步迁移为模板文件：

```text
vulnversion/prompts/
  stage1_chunk_v1.md
  stage1_chunk_v2.md
  stage1_chunk_v3.md
  stage2_rci_v1.md
  stage2_rci_v2.md
  stage2_rci_v3.md
  stage3_verdict_v1.md
  stage3_verdict_v2.md
  stage3_verdict_v3.md
```

每次运行记录：

```json
{
  "prompt_name": "stage3_verdict",
  "prompt_version": "v2",
  "prompt_hash": "...",
  "memory_bundle_hash": "...",
  "backend": "opencode|codex|claude_agent|replay"
}
```

### 15.2 第一轮优化：结构化、证据闭环、输出稳定

第一轮目标不是追求最高准确率，而是解决 Agent 输出不稳定、证据引用不足、职责边界不清、JSON 失败和泛化规则混乱的问题。

#### Step1 Prompt 第一轮：Chunk Role Schema Hardening

当前 Step1 容易把重构、测试、文档、格式化、依赖更新误判为漏洞修复。第一轮应将 chunk role 判断改为两阶段输出：

1. 先识别 chunk effect。
2. 再判断是否参与 vulnerability repair。

建议 Step1 prompt 增加固定判定维度：

```text
chunk_effect:
  - control_flow_change
  - data_validation_change
  - memory_safety_change
  - authz/authn_change
  - error_handling_change
  - API_contract_change
  - test_only
  - documentation_only
  - refactor_only
  - formatting_only

security_relevance:
  - directly_blocks_root_cause
  - enables_fix
  - validates_fix
  - unrelated_to_vulnerability
```

输出 schema 应扩展为：

```json
{
  "chunk_id": "...",
  "role": "PRIMARY_FIX|SUPPORTING_FIX|CONTEXTUAL_CHANGE|UNRELATED",
  "chunk_effect": "...",
  "security_relevance": "...",
  "negative_rationale": "...",
  "evidence_refs": [],
  "uncertainty": null
}
```

第一轮验收指标：

1. JSON parse failure 下降。
2. `evidence_refs` 非空率提升。
3. test/doc/refactor chunk 的误召回下降。
4. Stage2 输入 chunk 数量更稳定。

#### Step2 Prompt 第一轮：RCI Schema Hardening

当前 Step2 风险是 RCI 字段齐全但语义不够可执行。第一轮应强调 RCI 是“跨版本可判定定理”，不是 patch 总结。

Prompt 中必须强制 Agent 区分：

```text
root_cause:
  漏洞为什么发生

vulnerable_mechanism:
  漏洞存在时源码必须满足什么结构

fix_mechanism:
  修复通过什么结构阻断漏洞

cross_version_anchor:
  历史 tag 中如何找到同一机制

weak_signals:
  看起来相关但不能直接作为 predicate 的信号
```

第一轮输出应强制每个 predicate 给出：

```json
{
  "id": "vp1",
  "kind": "token_all|token_any|regex|ordered_tokens|proximity",
  "scope": {
    "file": "...",
    "function": "...",
    "must_be_localized": true,
    "excluded_paths": ["tests/", "docs/"]
  },
  "evidence": [],
  "why_discriminative": "...",
  "known_false_positive_risk": "..."
}
```

第一轮验收指标：

1. predicate 都有 scope。
2. weak signals 不再混入 fix_predicates。
3. `anchor_at_vuln` 非空率提升。
4. `metadata.risk_flags` 更稳定。

#### Step3 Prompt 第一轮：Verdict Output Hardening

当前 Step3 最大问题是 evidence 和 verdict 的绑定不够强。第一轮应改为先输出 predicate evaluation，再输出 final verdict。

建议输出 schema：

```json
{
  "tag": "...",
  "line": "...",
  "predicate_evaluations": [
    {
      "predicate_id": "vp1",
      "status": "matched|failed|not_applicable|unknown",
      "localized": true,
      "evidence_refs": [],
      "risk": "..."
    }
  ],
  "fix_evaluations": [],
  "guard_evaluations": [],
  "evidence_conflicts": [],
  "verdict": "AFFECTED|NOT_AFFECTED",
  "confidence": 0.0,
  "reasoning_summary": "..."
}
```

第一轮验收指标：

1. verdict 有 predicate-level 支撑。
2. `NOT_AFFECTED` 必须有 fix/absence/guard 三类证据之一。
3. evidence snippet 的 ref 可回放。
4. parse failure 和 malformed verdict 下降。

### 15.3 第二轮优化：安全语义推理和阶段专用策略

第二轮目标是提高漏洞语义准确率。每个 step 的优化方式不同。

#### Step1 Prompt 第二轮：Patch Intent Decomposition

Step1 不应只问“这个 chunk 是否相关”，而要要求 Agent 识别 patch intent。

Prompt 增加安全专家检查表：

```text
For each chunk, identify whether it changes:
1. input validation or bounds checks
2. object lifetime or ownership
3. integer size/cast/overflow behavior
4. authentication/authorization condition
5. parser state machine or protocol state
6. escaping/encoding/sanitization
7. error handling that prevents unsafe continuation
8. configuration or feature gate that changes exploitability
```

Role 判定规则：

```text
PRIMARY_FIX:
  Directly changes the vulnerable mechanism or the fix mechanism.

SUPPORTING_FIX:
  Required for primary fix to compile, propagate, or enforce safely.

CONTEXTUAL_CHANGE:
  Helps understand patch but does not block the root cause.

UNRELATED:
  Tests, docs, refactor, formatting, unrelated cleanup, broad dependency churn.
```

第二轮 Step1 还应引入 negative examples memory：历史上误判为 PRIMARY_FIX 的 test/doc/refactor chunk。

#### Step2 Prompt 第二轮：Root Cause Model and Predicate Design

Step2 prompt 应从“生成 RCI”升级为“构造漏洞存在性定理”。建议要求 Agent 用如下内部模型组织输出：

```text
Vulnerability Existence Theorem:
  A version is affected iff:
    1. vulnerable feature/mechanism exists
    2. trigger condition can reach vulnerable sink/state
    3. missing or insufficient fix/guard condition
    4. no guard invalidates exploit mechanism
```

对不同漏洞类别给出专用关注点：

```text
Memory safety:
  source buffer/length, sink, bounds check, allocation size, lifetime.

Information exposure:
  secret source, propagation path, encoding/filtering, output sink.

Injection:
  untrusted input, escaping/sanitization, command/query construction, sink.

Auth/authz:
  principal, privilege check, protected action, bypass condition.

Parser/state machine:
  state transition, malformed input handling, early exit/continuation behavior.
```

第二轮 Step2 输出必须增加：

```json
{
  "theorem": {
    "affected_if": [],
    "not_affected_if": [],
    "ambiguous_if": []
  },
  "predicate_design_notes": {
    "strong_signals": [],
    "weak_signals": [],
    "excluded_generic_tokens": []
  }
}
```

#### Step3 Prompt 第二轮：Evidence Adjudication Policy

Step3 prompt 需要从“检查 token”升级为“证据裁决”。核心策略：

```text
Evidence priority:
1. localized source code in anchor function
2. localized relocated equivalent
3. nearby call chain evidence
4. repo-wide grep matches
5. memory hints

Repo-wide grep alone cannot prove fix or vulnerability.
Header-only macro existence cannot prove a fix is applied.
Test-only evidence cannot prove production vulnerability status.
```

第二轮 Step3 增加 security verdict checklist：

```text
Before AFFECTED:
  - vulnerable mechanism exists in production code
  - vuln predicates are localized
  - no relevant fix predicate is localized
  - guards do not invalidate the root cause

Before NOT_AFFECTED:
  - localized fix structure exists, OR
  - vulnerable feature/mechanism is absent after rename-aware search, OR
  - implementation is materially different and guard evidence explains why root cause cannot occur
```

第二轮验收指标：

1. FP from generic token overmatch 下降。
2. FN from anchor missing 下降。
3. evidence conflict 被显式记录。
4. backend 间 verdict disagreement 下降。

### 15.4 第三轮优化：Hard-Case Driven Self-Evolving Prompts

第三轮目标是让 prompt 优化从人工规则进入数据驱动闭环。此轮不能直接让 Agent 自己改线上 prompt，必须通过 verifier gate。

#### Step1 Prompt 第三轮：Chunk Hard Case Mining

输入：

1. Stage1 chunk roles。
2. Stage2 RCI 失败或低质量案例。
3. Stage3 FP/FN 反向定位到 Step1 chunk selection 的案例。

生成：

```text
chunk_role_failure_memory
stage1_negative_examples
stage1_prompt_patch_candidate
```

第三轮 Step1 prompt 只允许增加两类内容：

1. 高价值 negative examples。
2. 更精确的 role boundary rule。

禁止增加过多通用安全常识，避免 prompt 变长但无收益。

#### Step2 Prompt 第三轮：RCI Failure Repair

输入：

1. predicate_overmatch failure。
2. predicate_undermatch failure。
3. guard_misfire failure。
4. anchor relocation failure。
5. same-label bisect unsafe cases。

生成：

```text
rci_prompt_patch_candidate
predicate_design_skill
guard_design_skill
anchor_design_skill
```

第三轮 Step2 prompt 优化重点：

1. 哪类 signal 应从 predicate 移入 weak_signals。
2. 哪类 anchor 必须加入 alternative_tokens。
3. 哪类 guard 不能作为 NOT_AFFECTED 充分条件。
4. 哪类 CWE 需要额外 theorem fields。

#### Step3 Prompt 第三轮：Verdict Failure Repair

输入：

1. FP / FN tag verdict。
2. evidence snippets。
3. current RCI。
4. ground truth only as oracle signal，不直接注入 prompt。
5. backend disagreement cases。

生成：

```text
stage3_prompt_patch_candidate
verdict_calibration_skill
evidence_priority_skill
rename_search_skill
```

第三轮 Step3 prompt 优化重点：

1. 增强高频错误类型的 decision policy。
2. 将重复失败模式转化为 compact skill。
3. 对 timeout 类问题减少不必要 tool search。
4. 对 parse failure 类问题强化 output schema。

#### 第三轮 Verifier Gate

所有 prompt patch candidate 必须经过：

```text
schema_gate:
  新 prompt 输出仍能被 parser 接受。

replay_gate:
  历史 trace 回放不出现字段缺失。

validation_gate:
  validation CVEs 上目标指标提升或不退化。

cost_gate:
  prompt token、latency、timeout 不显著上升。

leakage_gate:
  prompt patch 不包含 GT affected tag 或具体答案。
```

只有通过 gate 的 prompt patch 才能晋升为新版本。

### 15.5 Prompt A/B 实验矩阵

Prompt 优化必须做矩阵实验：

| 实验 | Step1 Prompt | Step2 Prompt | Step3 Prompt | 目的 |
|---|---|---|---|---|
| P0 | current | current | current | baseline |
| P1-S1 | v1 | current | current | 测 Step1 第一轮收益 |
| P1-S2 | current | v1 | current | 测 Step2 第一轮收益 |
| P1-S3 | current | current | v1 | 测 Step3 第一轮收益 |
| P1-All | v1 | v1 | v1 | 第一轮整体收益 |
| P2-All | v2 | v2 | v2 | 安全语义增强收益 |
| P3-All | v3 | v3 | v3 | hard-case 自进化收益 |

必要时增加交叉实验，确认收益来自哪一阶段。

### 15.6 Prompt / Memory / Skill 的边界

Prompt 中应写稳定任务规则；memory 中应写任务相关、repo 相关或历史 case 相关上下文；skill 中才写已经验证、可跨 case 复用的紧凑规则或流程。

| 内容 | Prompt | Memory | Skill |
|---|---|---|---|
| 输出 schema | 是 | 否 | 否 |
| evidence priority | 是 | 可补充 case context | 是，若已由 case pack 验证为可复用规则 |
| repo path alias | 否 | 是 | 否，除非多个 case 证明它可抽象为通用 rename-search rule |
| CVE-specific RCI / predicate reliability | 否 | 是 | 否，除非提炼为跨 CVE predicate design rule |
| CWE 通用漏洞机制 | 是，简短 | 是，详细 | 是，若形成可操作 checklist |
| 历史 FP/FN 归因 | 否 | 是 | 否，原始失败不能直接当 skill |
| 已验证 procedural rule | 可注入 | 保存来源与证据 | 是 |
| backend workaround | 否，除非 harness 层处理 | backend memory | 只能是 backend-specific skill，不能当漏洞语义规则 |

晋升规则：

1. Memory 先服务于上下文补全，不默认晋升 skill。
2. 只有当多个 case pack 证明某条 memory 中的“做法”可跨 case 复用，才允许生成 candidate skill。
3. Candidate skill 必须通过 replay gate、小样本验证和 leakage gate，才能成为 verified skill。
4. 含有具体 CVE 答案、GT、affected tags、neighbor verdict 或 affected range 的内容不得晋升 skill。
5. 如果一条规则可以用 deterministic Python 稳定实现，应优先晋升为 ArtifactMemory，而不是长期作为 prompt skill。

## 16. Artifact-Centric Evolution

VulnVersion 不应让 Agent 每次重新学习 repo 和验证策略。稳定经验应沉淀为 artifacts。

### 16.1 Artifact 层级

| Artifact | 来源 | 用途 |
|---|---|---|
| repo_adapter.json | RepoMemory | 路径、tag、line、目录规则 |
| stage1_chunk_rules.json | Step1 procedural memory | chunk role prefilter |
| rci_template_bank.json | RCIMemory | Step2 prompt and validation |
| predicate_repair_rules.json | FailureMemory | 修正过宽/过窄 predicates |
| anchor_relocation_policy.json | Repo/LineMemory | Stage3 anchor relocation |
| verdict_calibration_rules.json | FailureMemory | Stage3 verdict high-bar policy |

### 16.2 Artifact 晋升标准

1. 来自多条 memory。
2. 至少覆盖两个 CVE 或多个 release line，除非作用域明确限定。
3. validation replay 提升目标指标或降低成本。
4. 不引入显著 FP/FN 回归。

## 17. 实验设计

### 17.1 主要消融

| 配置 | 说明 |
|---|---|
| Base | 当前 VulnVersion |
| + Harness Abstraction | 仅替换 runtime interface |
| + Typed Memory | 使用 typed memory，但不注入 skill |
| + Procedural Memory | 注入过程记忆 |
| + SkillMemory | 注入 verified skills |
| + ArtifactMemory | 使用可执行 artifacts |
| + Full Self-Evolution | 完整闭环 |

### 17.2 Backend 对比

| Backend | No Memory | Typed Memory | Full VulnMem |
|---|---|---|---|
| OpenCode |  |  |  |
| Claude Code |  |  |  |
| Codex |  |  |  |
| Replay |  |  |  |

### 17.3 指标

任务指标：

1. Precision。
2. Recall。
3. F1。
4. FP / FN。
5. GT coverage。
6. unmapped GT rate。

Agent 指标：

1. JSON parse failure rate。
2. timeout rate。
3. AGENT_ERROR rate。
4. average latency per tag。
5. average tool calls per tag。
6. average prompt tokens。
7. evidence localization rate。
8. Stage3 tag judge accuracy：默认主路径必须 `>= 95%`。
9. Stage3 tag judge precision / recall / F1：只统计真实 Agent probed tag verdict，不混入 deterministic inference。
10. error amplification：报告单 tag judge error 对 per-CVE exact match、micro precision、micro recall、micro F1 的影响。

Memory/self-evolution 指标：

1. memory acceptance rate。
2. memory rejection rate。
3. harmful memory rate。
4. skill promotion success rate。
5. artifact promotion success rate。
6. hard case recurrence reduction。

## 18. 代码落地计划

### 18.1 Phase A: Harness 解耦

新增：

```text
vulnversion/agent_harness/
```

修改：

1. Stage1 从 `OpenCodeAgent` 改为 `AgentRuntime`。
2. Stage2 从 `OpenCodeAgent` 改为 `AgentRuntime`。
3. Stage3 从 `OpenCodeAgent` 改为 `AgentRuntime`。
4. 保留 OpenCodeRuntime 作为现有行为兼容层。
5. 增加 ReplayRuntime。

### 18.2 Phase B: Memory Schema 和 Store

新增：

```text
vulnversion/agent_harness/memory/
  schema.py
  manager.py
  retrieval.py
  updates.py
```

先使用 JSONL store，后续再考虑 SQLite/vector index。

### 18.3 Phase C: Trace and Failure Attribution

新增：

```text
vulnversion/self_evolve/
  trace_loader.py
  hard_cases.py
  failure_attributor.py
  memory_skill_controller.py
  verifier_gate.py
```

新增 case pack 目录：

```text
Result_agent_enhance_cases/
```

先离线读取 `Result/*/*` 和 `agent_calls/index.jsonl`，不要立即侵入主流程。任何 memory、skill、prompt 或 self-evolution 方案必须先形成 `agent_enhance_cases/<enhancement_id>/` case pack；没有 case pack 的方案只能保持 `hypothesis`。

当前源码落地的 Phase C v0 范围：

```text
vulnversion/self_evolve/
  schema.py              # AgentEnhanceCase / CasePackManifest / FailureAttribution
  trace_loader.py        # 发现 Result/*/*，读取 eval、verdict、trace、calls index
  hard_cases.py          # 从 per_tag_verdict.jsonl 抽取 FP/FN/UNKNOWN/TIMEOUT/JSON_ERROR/AGENT_ERROR
  failure_attributor.py  # 区分 stage3 agent judge、legacy agent judge、deterministic non-agent
  case_pack.py           # 生成 Result_agent_enhance_cases/<enhancement_id>/
tests/build_agent_enhance_cases.py
```

v0 只生成离线 evidence pack，不调用 OpenCode/Codex/Claude，不修改主流程，不启用 memory/skills 注入。生成的 `replay_summary.json` 与 `small_sample_summary.json` 默认是 `not_run`，因此 case pack 的状态仍是 `hypothesis`。只有后续通过 ReplayRuntime gate、小样本 OpenCode 验证和 leakage gate，才能进入 `read_only memory injection` 或 verified skill promotion。

`failure_attributor.py` 必须保留 Agent 边界：`verdict_source=agent/agent_error` 或旧版无 `verdict_source` 但包含 agent-style evidence/predicate 字段的 `OK/PARTIAL_PARSE` 行，才可标记为 agent judge relevant；`PREFILTER`、`BISECT_INFER`、`INFERRED` 和 fixed/inferred verdict source 属于 deterministic planner/artifact，不得作为 agent prompt/memory/skill 优化依据。

### 18.4 Phase D: Stage-specific SkillBank 脚手架

新增：

```text
vulnversion/agent_harness/skills/
  stage1_chunk/
  stage2_rci/
  stage3_verify/
```

修改：

1. 定义 stage skill metadata schema。
2. 增加每个 stage 的 `SKILL_INDEX.json`。
3. 实现 stage skill selector，只允许注入 verified skills。
4. 记录 selected/suppressed skills 到 agent trace。
5. 先落地每个 stage 的 2-3 个核心 seed skills，再由 hard cases 继续进化。

### 18.5 Phase E: Prompt 模板化和第一轮 Prompt 优化

新增：

```text
vulnversion/agent_harness/prompts/
```

修改：

1. 将 Stage1/2/3 prompt 从内联字符串迁移到版本化模板。
2. 增加 prompt name/version/hash 记录。
3. 实现 v1 prompt：schema hardening、evidence closure、output stability。
4. 加入 prompt A/B 配置。

### 18.6 Phase F: Stage3 Memory Injection

优先增强 Stage3，因为其反馈最直接。

进入条件：

1. 至少一个 Stage3 memory enhancement 已生成 `agent_enhance_cases/<enhancement_id>/case_index.jsonl`。
2. ReplayRuntime 已对相关历史 traces 完成回放，且 `replay_summary.json` 无不可解释 miss。
3. 小样本 OpenCode 验证通过，且 `small_sample_summary.json` 记录 improved/regression/unchanged cases。
4. 通过 leakage gate，确认 memory 不包含 GT affected tags、affected range、neighbor verdict 或 planner state。
5. 只有满足以上条件后，才允许从 `memory_mode="off"` 进入 `memory_mode="read_only"`；`write_candidate` 和 `full` 仍需额外 verifier gate。

修改：

1. `_build_navigation_prompt` 支持 memory block。
2. `_verify_single_tag_llm` 在构造 prompt 前检索 memory。
3. tag verdict 后写入 EvidenceMemory / LineMemory。
4. eval 后写入 FailureMemory。

### 18.7 Phase G: Step1/Step2 Memory Injection

1. Step1 注入 chunk role memory。
2. Step2 注入 RCI/predicate/guard memory。
3. Step2 输出后运行 deterministic RCI quality checker。

### 18.8 Phase H: 第二轮和第三轮 Prompt 优化

1. 第二轮：加入安全语义推理、阶段专用策略和 evidence adjudication。
2. 第三轮：基于 hard cases 自动生成 prompt patch candidate。
3. 所有 prompt patch 必须经过 schema/replay/validation/cost/leakage gate。

### 18.9 Phase I: Skill and Artifact Promotion

1. 从 FailureMemory 生成 ProceduralMemory。
2. 通过 verifier gate 晋升 SkillMemory。
3. 多轮稳定后编译 ArtifactMemory。

## 19. 维护规范

后续如果修改以下内容，必须同步更新本文档：

1. Agent runtime interface。
2. OpenCode / Claude / Codex harness 行为。
3. Stage1/2/3 prompt。
4. Memory schema。
5. Memory retrieval / injection 策略。
6. Enhancement scope、namespace、precedence、promotion 规则。
7. Self-evolution pipeline。
8. Stage-specific SkillBank、skill selector、skill verifier gate。
9. Skill promotion / artifact promotion 规则。
10. Prompt 模板、prompt version、prompt A/B 实验配置。
11. 实验指标或消融设置。

每次更新建议在文档末尾追加 change log。

## 20. Change Log

| 日期 | 修改 |
|---|---|
| 2026-04-29 | 初版。定义 VulnMem-Agent Layer、typed memory、memory operation skills、self-evolution、harness 解耦和三阶段增强方案。 |
| 2026-04-30 | 增加三轮 Prompt 优化方案：第一轮结构化与证据闭环，第二轮安全语义推理，第三轮 hard-case driven self-evolving prompts；同步调整代码落地计划与维护规范。 |
| 2026-04-30 | 增加 Stage-Specific Self-Evolving Skill Systems：为 Step1/Step2/Step3 分别定义独立 SkillBank、skill package schema、controller、自进化闭环、verifier gate 和落地 phase。 |
| 2026-05-01 | 强化 Planner / Judge separation：明确 Agent 只做判别，不做 tag plan、scan order、ASBS probe、early-stop 或 affected range aggregation；相关 planner 信息不得作为当前 tag verdict 证据注入。 |
| 2026-05-01 | 增加 Enhancement Scope and Precedence：定义 Global/Backend/Stage/CWE/Repo/CVE/Line/Tag/Experiment 作用域、namespace、检索规则、冲突优先级、跨 scope 晋升和注入策略。 |
| 2026-05-01 | 落地 OpenCode-first `agent_harness` 源码脚手架：新增 `AgentRuntime` 协议、`OpenCodeRuntime` 兼容层、Codex/Claude 预留 runtime、Replay 占位、trace/prompt/memory/skills 脚手架；明确 `.opencode/skills` 只属于 OpenCode native skills，不自动跨 backend 共享。 |
| 2026-05-02 | 接入 `AgentService` 透明代理和调用级 trace：`main.py` 按 CVE 创建 `agent_trace.jsonl`，Stage1/2/3 的 `run_json` metadata 写入 stage/task/cve/tag/chunk 信息；JSON 解析仍保留在 OpenCodeAgent 兼容层。 |
| 2026-05-02 | 强化 OpenCode adapter 可审计能力：`OpenCodeRuntime.diagnostics()` 记录 health、provider/model、native `.opencode/skills`、native tools 和 readonly permissions；`AgentService` 跟踪 known sessions，并在 worker 中写入 `agent_runtime.json`、`agent_sessions.json` 和 `opencode_messages_all.jsonl`。 |
| 2026-05-02 | Phase 1 Prompt Provenance：新增 `PromptSpec` / `PromptProvenance`，将当前 Stage1/2/3 Python prompt builder 登记为 `stage1_chunk_v0`、`stage2_rci_v0`、`stage3_verdict_v0`，并在 trace 中记录 prompt name/version/schema/builder/hash。 |
| 2026-05-02 | Phase 2 Stage1 AgentTask：Stage1 chunk role 判断已从直接 `run_json` 迁移到 `AgentTask` + `AgentService.run_task()` 优先路径，并记录 `judgement_only` 与 `forbidden_context`；Stage2/3 暂不迁移。 |
| 2026-05-02 | Phase 3 Trace and Status Hardening：扩展 `tests/check_agent_enhance_status.py`，新增 prompt provenance、trace provenance、Stage1 AgentTask 边界检查，当前静态状态为 `20 passed, 0 failed`。 |
| 2026-05-02 | Phase 4 ReplayRuntime 设计准备：新增 `ReplayRuntimePlan`，明确 v1 应基于 `agent_trace.jsonl` 的 prompt provenance 和 parsed output artifact 回放；当前保持 `reserved_not_executable`，不可声明为实验 backend。 |
| 2026-05-02 | 地基层收口：`AgentService.run_json()` 新增 `agent_calls/<trace_id>.parsed.json`、prompt/system artifact 和 `index.jsonl`；trace 记录 parsed/prompt/system path；ReplayRuntime v1 已可本地读取 `agent_calls/index.jsonl` 回放 parsed JSON，但未 batch validated。 |
| 2026-05-02 | Stage2/Stage3 迁移到 `AgentTask` 优先路径：Stage2 RCI induction 和 Stage3 single-tag verdict 均记录 `judgement_only` 与 forbidden_context，保留 direct runtime fallback，不改变 prompt 文本或输出 schema。 |
| 2026-05-02 | 新增 harness mode config 与 injection audit stub：`VV_MEMORY_MODE`、`VV_SKILL_MODE`、`VV_REPLAY_MODE` 可配置；trace metadata 预留 retrieved_memory_ids、selected_skills、suppressed_skills 和 injection_policy，但当前不注入 memory/skills。 |
| 2026-05-02 | 增加 Evidence-first Agent Enhancement Gate：新增 `Result_agent_enhance_cases/` case pack 规范；所有 memory/skills/prompt/self-evolution 方案必须先有 case pack、ReplayRuntime 回放和小样本验证，才允许进入 `read_only memory injection`。 |
| 2026-05-02 | 强化 Memory / Skills 边界：memory 定义为上下文补全和判别辅助，skills 仅保存可复用、可触发、可验证的规则、流程或操作策略；只有经过 case pack、replay 和小样本验证的 memory-derived procedure 才能晋升为 skill。 |
| 2026-05-02 | 增加 Stage3 Tag Judge Accuracy Floor：Agent 对 planner 给定 tag 的单 tag 判别准确率必须达到 95% 以上才允许进入默认主路径，并要求单独报告 probed tag verdict 指标和 error amplification。 |
| 2026-05-02 | 增加 Step3 tag plan 稳定后的 Agent judge 能力增强章节：明确后续不再由 Agent 优化 tag plan，而是围绕 evidence localization、root cause alignment、predicate evaluation、guard/fix adjudication、uncertainty calibration 和 JSON/schema stability 增强 Step1/2/3 判别链。 |
| 2026-05-03 | Phase C v0 源码落地：新增 `vulnversion/self_evolve` 和 `tests/build_agent_enhance_cases.py`，可从现有 `Result/*/*` 离线生成 `Result_agent_enhance_cases/<enhancement_id>/` case pack；当前仅为 hypothesis evidence，不启用 memory/skills 注入。 |
| 2026-05-04 | OpenCode-native skills 与 memory candidate 地基落地：新增 `tests/check_opencode_skills.py`，升级 `.opencode/skills/git-navigation` judge-only workflow，增加 `cwe-skills` learned overlay，新增 memory candidate store、leakage gate、promotion gate 和本地检查；当前仍不启用 memory/skills prompt injection。 |
| 2026-05-06 | 清理 Stage3 废弃运行参数：从 `main.py`、`run_stage3()` 和 `verify_tags()` 删除无效的 `--all-tags`、`--max-tags`、`--early-stop-n`、`early_stop_n`、`bisect_enabled` 兼容路径，并在状态检查中要求这些假控制参数不得回归。 |
| 2026-05-11 | 增加 Stage3 prompt v1 设计：保留 `stage3_verdict_v0=legacy_navigation`，新增 `stage3_verdict_v1=target_tag_theorem_judge`，要求围绕 Step2 漏洞存在性定理对 planner 给定 tag 做单 tag 判别，并定义 v0/v1 A/B 指标。 |
| 2026-05-11 | 压缩 Stage3 v1 prompt 并修复 `n0.11.4` ERROR regression：v1 prompt 明确写入目标 repo path，并要求所有 git 命令使用 `git -C <repo_path>`，避免 OpenCode 在 VulnVersion 工程根目录误查 tag。 |
| 2026-05-11 | 修复 A/B evaluator：正确解析 OpenCode `opencode_messages_all.jsonl` 的 session-wrapped `messages` 格式，并将 baseline UNKNOWN/ERROR 到 candidate correct 的变化计入 improved cases；3-CVE Stage3-only A/B 显示 v1 为 3 improved / 0 regression。 |
| 2026-05-13 | 完成 8-CVE / 40-tag Stage3-only cost gate：v1 为 10 improved / 0 regression，UNKNOWN 11->1，latency、tool calls 和完整 message JSON 体量均低于 v0；Stage3 默认 prompt version 切换为 v1，v0 保留为显式 deprecated baseline。 |
