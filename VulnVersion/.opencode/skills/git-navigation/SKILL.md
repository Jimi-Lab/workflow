---
name: git-navigation
description: OpenCode-native 只读 Git 导航与取证技能。用于 VulnVersion 的 judge-only 阶段，在特定 commit、tag、branch 上读取代码、搜索符号、追踪重命名、分析版本拓扑，并用可复核的 Git 证据支撑漏洞判断。
---

# Git Navigation

这是一个 OpenCode-native procedural skill，只服务当前 OpenCode backend。它不是 VulnVersion canonical skill，也不能直接复用于 Codex/Claude。

它不替代 `vulnversion/git_ops` 的 Python 封装；它的作用是让 agent 在需要直接操作 Git 时，遵循稳定、可复核、低误判的导航策略。

## VulnVersion Judge-only Boundary

- Stage 1 只支持 patch chunk relevance 判断，不输出 affected versions。
- Stage 2 只支持 root cause、anchor、vuln/fix predicates、guards 的证据构造。
- Stage 3 只支持 planner 给定 tag 的单 tag verdict。
- 不做 tag plan、scan order、early stop、affected range aggregation。
- 不使用 GT affected tags、neighbor verdicts、advisory ranges 或 planner state 作为 verdict evidence。

## When To Use

在以下任务中使用本技能：

- 需要读取某个 tag/commit 的真实代码，而不是工作区文件
- 需要定位函数、宏、常量、错误码、wrapper 或 guard
- 需要判断文件是否存在、是否重命名、是否迁移
- 需要判断 fix commit 是否传播到某条 release line
- 需要为漏洞判断提供 Git 级证据

## Hard Rules

1. 默认面向只读取证，不做 checkout、不改 working tree。
2. 判断某个 tag 时，必须读取 `tag:path`，不要偷看工作区文件。
3. `git grep` 只能定位，不能单独作为最终结论。
4. 命中 token 后，必须用 `git show` 或等价命令读取上下文。
5. 优先固定字符串搜索；只有确实需要模式时才用 regex。
6. 遇到路径不存在，不要立刻判“代码消失”；先查 rename/move。
7. 涉及 tag 传播时，优先用 topology 命令而不是凭名称猜测。
8. 当前 tag 的代码证据优先级高于 commit message、CWE 先验和 advisory 文本。

## Core Workflow

1. 先读 [references/revision-selection.md](references/revision-selection.md)。
2. 读取某个版本的文件或目录时，读 [references/snapshot-navigation.md](references/snapshot-navigation.md)。
3. 搜符号或 token 时，读 [references/code-search.md](references/code-search.md)。
4. 查来源、rename、引入点时，读 [references/history-and-rename.md](references/history-and-rename.md)。
5. 分析 fix 传播、祖先关系、release line 时，读 [references/tag-and-topology.md](references/tag-and-topology.md)。
6. 做最终判断前，读 [references/evidence-discipline.md](references/evidence-discipline.md)。

## Failure-triggered Workflow

遇到以下情况时必须降级为更谨慎的证据流程：

- path missing：先做 `git cat-file`、`git ls-tree`、rename/move 和 topology 检查。
- generic token overmatch：只把 token 当定位线索，回到函数窗口确认 relation。
- fix-token overmatch：确认 fix relation 是否和 root cause 同一作用域，避免把相似 guard 当补丁。
- rename/move ambiguity：先建立旧路径和新路径的映射，再判断漏洞逻辑。
- weak negative evidence：不能只因 grep miss 输出 `NOT_AFFECTED`，必须解释 anchor 缺失、代码迁移或 fix relation。

## Stage Routing

- Stage 1: 读 [references/stage1.md](references/stage1.md)
- Stage 2: 读 [references/stage2.md](references/stage2.md)
- Stage 3: 读 [references/stage3.md](references/stage3.md)

## Fast Heuristics

- 读文件：`git show <ref>:<path>`
- 查路径是否存在：`git cat-file -e <ref>:<path>`
- 列目录：`git ls-tree --name-only <ref> <dir>/`
- 精确搜 token：`git grep -F -n '<token>' <ref> -- '*.c' '*.h'`
- 读局部上下文：`git grep -n -C 3 '<pattern>' <ref>`
- 查 rename：`git log --follow --name-status -- <path>`
- 查引入点：`git log -S'<token>' --oneline <range>`
- 查语义模式：`git log -G'<regex>' --oneline <range>`
- 查函数/行历史：`git log -L :<func>:<file> <range>`
- 查 blame：`git blame --line-porcelain -L <start>,<end> <ref> -- <file>`
- 查传播：`git tag --contains <commit>`
- 查共同祖先：`git merge-base <a> <b>`
- 查祖先路径：`git rev-list --ancestry-path <older>..<newer>`

## Output Discipline

当你使用本技能时：

- 明确说明当前读的是哪个 `ref`
- 明确说明证据来自哪个文件和行
- 若路径不存在，写清楚你是否做过 rename/topology 检查
- 不要只复述命令输出，要给出与漏洞判断相关的结论
