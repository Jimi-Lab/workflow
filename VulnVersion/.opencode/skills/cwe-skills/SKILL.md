---
name: cwe-skills
description: 这个 skills 包括了全部的 CWE 类型。若任务中出现特定的 CWE-ID，则按当前阶段按需读取对应的 CWE stage 文件；不要直接读取原始 XML。
---

# CWE Skills Router

这是一个 OpenCode-native 路由型技能，不直接提供某个具体 CWE 的完整知识，而是指导你在需要时加载最小必要的 CWE 资料。

`references/by-id` 是 static base knowledge，由 CWE 官网资料脚本生成，可重建，不应由自学习流程直接覆盖。VulnVersion 的自学习、自进化内容只能进入 `references/learned` learned overlay，并且必须通过 case pack、ReplayRuntime、小样本 OpenCode 验证和 leakage gate。

## Purpose

当任务涉及以下活动时，优先使用本技能：

- 漏洞类型归因
- patch chunk 角色判断
- root cause 总结
- anchor 选择
- vuln/fix predicate 构造
- guard 设计
- tag 级验证
- FP/FN 误差分析

本技能的目标不是把全部 CWE 文本送入上下文，而是：

1. 根据 `CWE-XXX` 精确定位条目
2. 根据阶段只读取必要的 `stage1.md / stage2.md / stage3.md`
3. 避免读取原始大 XML
4. 控制上下文体积，优先使用结构化资料

## Directory Convention

相对本 skill 基目录，CWE 资料位于：

- `references/index.json`
- `references/meta.schema.json`
- `references/by-id/CWE-XXX/meta.json`
- `references/by-id/CWE-XXX/stage1.md`
- `references/by-id/CWE-XXX/stage2.md`
- `references/by-id/CWE-XXX/stage3.md`

可选家族视图位于：

- `references/by-family/CWE-YYY.md`

自学习 overlay 位于：

- `references/learned/README.md`
- `references/learned/candidates/`
- `references/learned/by-id/CWE-XXX/`

原始 XML 仅作为离线构建来源，不应在运行期直接读取。

## Routing Rules

### Rule 1: Specific CWE-ID present

如果输入中已有明确 `CWE-XXX`：

- Stage 1 任务：读取 `references/by-id/CWE-XXX/stage1.md`
- Stage 2 任务：读取 `references/by-id/CWE-XXX/stage2.md`
- Stage 3 任务：读取 `references/by-id/CWE-XXX/stage3.md`

只有在需要结构化背景字段时，再补读：

- `references/by-id/CWE-XXX/meta.json`

默认不要先读 `meta.json`。

### Rule 2: Multiple CWE-IDs present

若同时存在多个 CWE：

1. 优先读取更具体条目：
   `Variant > Base > Class > Pillar > Category`
2. 默认最多加载 2 个最相关 CWE
3. 若其中一个只是宽泛父类，优先读取具体子类

### Rule 3: Only broad family known

如果只有类似 `CWE-119`、`CWE-20` 这样的宽泛家族：

1. 先读 `references/by-family/CWE-119.md`
2. 再根据代码特征决定是否下钻到更具体的 `by-id` 条目

### Rule 4: No explicit CWE but type is inferable

若没有显式 `CWE-ID`，但从 CVE 描述、patch、root cause 可以推断漏洞类型：

1. 先推断最可能的 `CWE-XXX`
2. 再读取对应 stage 文件
3. 不要在没有证据时加载多个无关 CWE

## Stage-Specific Usage

### Stage 1

目标：帮助判断某个 chunk 更像：

- `PRIMARY_FIX`
- `SUPPORTING_FIX`
- `CONTEXTUAL_CHANGE`
- `UNRELATED`

只关注：

- 常见 root-cause 触点
- 典型 fix action
- 常见无关改动模式

### Stage 2

目标：帮助构造：

- `root_cause`
- `anchor`
- `vuln_predicates`
- `fix_predicates`
- `guards`

优先关注：

- mechanism summary
- preferred anchor choices
- predicate templates
- guard templates
- dangerous generic tokens
- preferred scopes

### Stage 3

目标：帮助验证某 tag 是否仍受影响。

优先关注：

- 高信号 fix/vuln 搜索顺序
- 哪些 token 可用于 prefilter
- 哪些 token 过于泛化不能单独作为证据
- 哪些负证据足以支持 `NOT_AFFECTED`

## Hard Constraints

1. 不要直接读取原始 `CWE-2000.xml`，除非任务明确要求做离线构建或重新解析。
2. 不要一次性加载多个无关 CWE 的完整资料。
3. 不要把 CWE 文本当作最终证据；CWE 只提供先验和搜索策略，最终结论必须回到代码证据。
4. Stage 3 默认只读 `stage3.md`，不要重复加载 Stage 1/2 内容，除非当前验证失败且需要回溯 root cause。
5. 若 `meta.json` 与 `stage*.md` 存在冲突，以 `meta.json` 的结构化字段为准，以 `stage*.md` 的行为建议为辅。
6. candidate overlay 不能默认注入；只有 verified overlay 才允许被 OpenCode skill router 读取。
7. learned overlay 不能包含 GT affected tags、affected range、neighbor verdict、planner state、tag plan、scan order 或 early stop。
8. 如果一条 learned rule 可以 deterministic Python 实现，应晋升为 ArtifactMemory，而不是长期保存在 CWE skill。

## Learned Overlay Gate

读取 learned overlay 前必须确认：

1. 来源是 `Result_agent_enhance_cases/<enhancement_id>/` case pack。
2. ReplayRuntime gate 已通过，且 replay summary 不是 `not_run`。
3. 小样本 OpenCode 验证已通过，且有 improved/regression/unchanged case report。
4. leakage gate 通过。
5. overlay status 是 `verified`，不是 `candidate` 或 `hypothesis`。

## Recommended Access Pattern

给定 `CWE-787`：

- Stage 1: `references/by-id/CWE-787/stage1.md`
- Stage 2: `references/by-id/CWE-787/stage2.md`
- Stage 3: `references/by-id/CWE-787/stage3.md`

若需要结构化背景，再读取：

- `references/by-id/CWE-787/meta.json`

## Output Discipline

使用本技能时：

- 先说明你选择的 `CWE-ID`
- 再说明当前阶段读取了哪个 stage 文件
- 仅把与当前阶段直接相关的规则带入后续推理
- 不要复述整个 CWE 文档
