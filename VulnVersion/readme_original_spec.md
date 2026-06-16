你是 GPT-5.2-Codex。请从零实现一个全新的漏洞分析系统：VulnVersion
系统目标：在不编译目标仓库、不使用静态分析工具（如 CodeQL）的前提下，基于 Git 历史与github源码文本+CVEid+CWEid，完成漏洞存在性定理（RCI / VET）的学习，并对历史版本逐一验证漏洞是否仍然存在。

系统面向 ISSTA 论文标准，强调：语义正确性、可执行性、可证伪性与跨版本鲁棒性。

========================
运行平台与开发环境（必须）
==========================

【支持平台】

- 主要支持：Ubuntu 22.04 LTS（x86_64）
- 兼容支持：Windows 10/11（本地开发与小规模运行）；

【系统级依赖（必须安装）】

- `git`（建议 >= 2.34）：用于 `git show/git grep/git tag/...` 等只读取证
- `conda`（Miniconda/Anaconda 均可）：本项目唯一支持的 Python 环境管理方式
- `python`（建议 3.11 或 3.12）：通过 conda 环境提供

【Conda 环境约束（必须）】

- 本项目 conda 环境在本地固定命名为：`VulnVersion`
- 所有运行命令默认在 `conda activate VulnVersion` 后执行
- Python 依赖必须通过 conda 环境统一管理，禁止混用系统 Python 与 `venv`

【OpenCode 依赖（必须安装其一）】

Stage 1/2/3 需要通过 OpenCode Agent 执行“只读、可证据化”的多步取证与判定：

- 推荐：安装并运行 OpenCode CLI/Server（版本建议对齐 `opencode-1.1.36`）
  - 运行模式：`opencode serve`（headless HTTP 服务）
  - 本项目作为 client 通过 HTTP 调用 OpenCode（不修改 OpenCode 源码）
- 备用：Embedded 模式（同进程 fetch handler），仅用于无网络/单机调试

【Python 软件包依赖（必须提前固定）】

依赖必须在 `environment.yml` 中固定版本范围，避免评测结果漂移。建议最小集合（core + 兼容层）：

- 核心（VulnVersion 运行所需）：
  - `pydantic`（2.x）：结构化 schema 与 JSON 校验
  - `jsonschema`（4.x）：对 artifacts 输出进行二次验证（可选但建议）
  - `httpx`（0.2x）或 `requests`（2.x）：OpenCode HTTP client 与外部抓取（二选一，最终实现固定其一）
  - `tqdm`（4.x）：批处理进度显示（可选）
  - `pyyaml`（6.x）：读取 repo 映射与配置（可选但建议）
- 兼容（RepoMaster/Repo 索引复用建议）：
  - `networkx`：图结构与重要性计算相关能力
  - `tree-sitter`：文本级语法树/符号抽取（如需要）
  - `tiktoken`：token 预算估算（如需要）
  - `grep-ast`：代码结构化 grep（如需要）

【LLM/模型侧依赖】

本项目不直接绑定某一家模型 SDK；模型访问交由 OpenCode 配置管理。本项目仅要求：

- OpenCode 侧可配置 `provider/model-id`
- 本项目仅通过 OpenCode API 触发 agent，不在本进程内直接调用模型 SDK

【LLM Base URL 与 API Key（必须，OpenAI 兼容格式）】

你后续提供的 LLM `base_url` 与 `api_key` 必须兼容 OpenAI API 格式（`/v1` 风格）。本项目约束：

1) 密钥不得写入仓库文件，必须通过运行环境注入（环境变量或本地 `.env`，不纳入版本控制）
2) OpenCode Server 必须能读取到以下等价配置（命名可按 OpenCode 侧实际配置对齐，但语义必须一致）：
   - `OPENAI_BASE_URL`：例如 `https://<your-host>/v1`
   - `OPENAI_API_KEY`
   - `OPENAI_MODEL`（可选，但建议固定）
3) VulnVersion 侧仅与 OpenCode 交互，不直接持有/转发 API Key 到 artifacts（避免泄露）

========================
数据集适配（必须）
==================

本系统需要对论文数据集 `/e:/AI/Agent/workflow/VulnScope/dataset/SZZdata/how far are we Dataset.json` 进行原生适配，用于：

1) 给定 `CVE -> repo + fix commit` 的自动化输入装配
2) 用 `affected_version` 作为“已知受影响版本（ground truth tags）”进行离线评测

【数据集结构（已确认：1128 条记录，字段固定）】

顶层是一个 JSON 对象：`{ "<CVE-ID>": <Record>, ... }`

每条 `<Record>` 的字段如下：

- `repo`: `str`，目标仓库的简称（例如：`linux` / `FFmpeg` / `curl` / `openssl` / `qemu` / `wireshark` / `httpd` / `ImageMagick` / `openjpeg`）
- `fixing_commits`: `list[list[str]]`，修复提交集合。常见形式为 `[[ "<commit>" ]]`，但必须按“二维列表”处理：
  - 外层 list 表示可能存在多个“修复路径/候选修复集合”（例如不同分支或不同补丁序列）
  - 内层 list 表示同一修复路径上的一个或多个 commits（例如 backport 链）
- `affected_version`: `list[str]`，数据集标注的“受影响版本标签”。默认将其视为 **git tag 名称集合** 用于评测（例如 `n4.3`、`n5.1.2`、`ffmpeg-0.6.3`、`v0.5.1`）
- `CWE`: `list[str]`，CWE 列表（例如 `["CWE-119","CWE-125"]`），用于引导 RCI 归纳（可作为先验，不得替代证据）

【重要约束与假设（必须写入实现）】

1) 数据集不包含 CVE 描述文本：系统必须通过外部来源获取（例如 NVD），或由用户输入 `--cve-desc` 提供。
2) `affected_version` 与仓库 tags 的命名可能不完全一致：实现必须支持“严格匹配模式”（只认同名 tag）与“宽松匹配模式”（可配置规范化规则，例如大小写/前缀差异），并对无法映射的版本输出 `INCONCLUSIVE` 且记录原因。
3) 默认只使用 `fixing_commits[0][0]` 作为 Stage 1 的 `fix commit`；但系统应支持按修复路径批处理（对 `fixing_commits[0]` 的多个 commit 逐个执行 Stage 1，并在 Stage 2/3 合并证据）。

【CVE 描述获取与缓存（必须）】

由于 Stage 1/2/3 的 OpenCode Agent 被约束为“只读、可证据化”且默认不依赖 `webfetch`，CVE 描述文本的获取必须在 agent 之外完成，并以“可追溯原文”的方式写入 artifacts：

1) 输入来源（至少支持其一）：
   - 用户显式传入 `--cve-desc`（或 `--cve-desc-file`）
   - 系统通过外部数据源抓取（例如 NVD API），但必须把原始响应（raw json/text）落盘保存
2) 证据要求：
   - `artifacts/<cve_id>/cve_desc.txt`：规范化后的描述正文
   - `artifacts/<cve_id>/cve_source.json`：原始来源响应（或其完整原文），包含获取时间与 URL/查询参数
3) agent 使用方式：
   - Stage 1/2/3 只读取上述 artifacts 文件作为 CVE 描述证据，不直接联网获取

========================
总体流程（必须严格按三阶段实现）
================================

Stage 1: Semantic Patch Aggregation（语义聚合，而非筛选）
Stage 2: RCI Generation via Navigation Agent（基于导航式 agent 的定理生成）
Stage 3: RCI-based Version Verification（基于 RCI 的跨版本静态匹配）

========================
统一 OpenCode Agent 抽象（必须）
================================

Stage 1 与 Stage 2 均需要使用 LLM，但两者的共同点是：LLM 必须在“只读、可证据化”的约束下工作，通过一组受限的文本导航工具获取证据并输出结构化 JSON。为避免重复实现与提示词漂移，系统必须抽象一个统一的 OpenCode Agent，并在 Stage 1/Stage 2 复用。

========================
OpenCode 最小改动复用设计（必须）
=================================

本项目不“移植” OpenCode，而是把 OpenCode 当成一个可复用的「会话化 Agent 执行内核 + Tool 扩展框架」来使用；本项目仅新增少量自定义只读工具与权限规则，不修改 OpenCode 核心逻辑。

【复用目标】

1) 复用 OpenCode 的 multi-step 工具调用编排与输出归档（session/message/part）
2) 复用 OpenCode 的 tool registry（动态加载自定义 tool）以最小成本扩展只读 Git 工具库（例如 `git_show/git_grep/git_diff/git_log/list_tags`）
3) 复用 OpenCode 的 permission gate，确保 Stage 1/2/3 严格“只读、可证据化”

【运行形态（两种后端，推荐 Server）】

后端 A：OpenCode Server（推荐）

- 启动：使用 `opencode serve` 起一个 headless HTTP 服务
- 调用：VulnVersion 作为 client，通过 HTTP SDK/API 调用 OpenCode 创建 session、提交消息、消费事件流
- 优点：与你的主系统解耦；同一套 Agent 可在 CI/集群/多机复用；审计与回放天然支持

后端 B：OpenCode Embedded（备用）

- 方式：在同一进程内用 OpenCode 的 Server App 作为 fetch handler（等价于“内置服务”）
- 适用：单机调试、无网络环境

【Tool 扩展点与加载流程（必须）】

OpenCode 支持在配置目录中扫描 `.opencode/{tool,tools}/*.{js,ts}` 并动态注册工具；同时支持 plugin 内定义工具。对应核心流程可参考 OpenCode：

- 动态扫描并构建 custom tools：`packages/opencode/src/tool/registry.ts`
- 扫描目录集合（全局 config + 项目 `.opencode` + 用户 home `.opencode`）：`packages/opencode/src/config/config.ts`

本项目的原则是：Stage 1/2/3 必须使用 OpenCode 内建只读工具进行证据采集（`read/grep/glob/list`），并且仅在需要时追加“只读 Git 工具库”；所有编辑类能力必须被彻底禁用（`edit/write/patch/multiedit`），同时禁止任何交互式编辑器命令（例如 `vim/nano`）。

【权限与工具白名单（必须）】

最小白名单必须包含（OpenCode 内建）：

- `read(path, start_line?, end_line?)`：读取工作区文件内容
- `grep(pattern, path_glob?)`：正则搜索工作区文件
- `glob(pattern)`：按 glob 匹配文件
- `list(path)`：列举目录内容

只读 Git 工具库（必须提供，作为 OpenCode 自定义 tools）：

- `git_show(ref, path, start_line?, end_line?)`：读取指定 ref 的文件片段（等价 `git show <ref>:<path>` + 行切片）
- `git_grep(ref, pattern, path_glob?)`：在指定 ref 上搜索（等价 `git grep -n <pattern> <ref> -- <path_glob>`）
- `git_diff(commit)`：读取指定 commit 的 patch（等价 `git show --patch <commit>`）
- `git_log(range_or_ref, path_glob?, max_commits?)`：读取提交历史（等价 `git log --oneline --decorate` + 可选路径过滤）
- `list_tags(tags_glob?, max_tags?)`：列举 tags（等价 `git tag -l` 或 `git for-each-ref refs/tags`）
- `git_ls_tree(ref, path?)`：列举树对象（等价 `git ls-tree`，用于确认文件是否存在）
- `git_cat_file(object, pretty?)`：查询对象类型/大小/内容摘要（等价 `git cat-file`，用于证据一致性校验）
- `git_rev_parse(rev)`：解析 rev（等价 `git rev-parse`，用于统一 ref 表示）
- `git_merge_base(ref_a, ref_b)`：计算共同祖先（等价 `git merge-base`，用于 tag/分支关系推断）
- `git_show_ref(ref_glob?)`：列举 refs（等价 `git show-ref`，用于确认 tag/branch 指向）

【Git 工具库接口规范（必须）】

Git 工具库必须满足：

1) 只读：工具实现不得调用任何会变更工作区或历史的 git 子命令（checkout/switch/reset/clean/commit/merge/rebase/cherry-pick/revert/stash/push/pull 等）
2) 可证据化：所有返回内容必须能直接进入 `evidence_pack`，并可复现（明确 `ref`、`path`、行号范围、原文片段）
3) 可限流：对大文件/大输出必须支持范围/条数限制（`start_line/end_line/max_*`），避免一次性吐出全仓内容
4) 结构化：返回必须为稳定 JSON 结构，避免把“解析责任”留给 LLM

推荐的最小返回结构（示例字段，可按实现微调但语义必须等价）：

- `git_show`：
  - `ref_resolved`: str
  - `path`: str
  - `start_line`: int
  - `end_line`: int
  - `lines`: list[{"no": int, "text": str}]
- `git_grep`：
  - `ref_resolved`: str
  - `pattern`: str
  - `matches`: list[{"path": str, "line": int, "text": str}]
- `git_diff`：
  - `commit`: str
  - `files`: list[{"path": str, "hunks": list[{"header": str, "removed": list[str], "added": list[str]}]}]
- `list_tags`：
  - `tags`: list[str]

权限规则必须满足：

1) `edit` 一律 `deny`（覆盖 `edit/write/patch/multiedit`），保证不可修改仓库
2) `bash` 默认 `deny`；如果为了兼容 `cat/rg/grep/head/tail` 这类只读命令必须启用 `bash`，则必须使用“精细化命令白名单”，并显式禁止：
   - 交互编辑器：`vim *`、`nano *`、`emacs *`
   - 任何会改变工作区/历史的 git：`git checkout*`、`git switch*`、`git reset*`、`git clean*`、`git commit*`、`git merge*`、`git rebase*`、`git cherry-pick*`、`git revert*`、`git stash*`、`git push*`、`git pull*`
3) Stage 1/2/3 的 OpenCode Agent 必须以“只读 ruleset”启动，确保行为层面不可越权

OpenCode 的 permission 判定机制可参考：

- `packages/opencode/src/permission/next.ts`

【会话归档与可复现实验轨迹（必须）】

OpenCode 会把 session、message、part 写入本地 Storage（JSON 结构化落盘），用于 UI 回放、审计和导出。对应实现可参考：

- `packages/opencode/src/session/index.ts`（session/message/part 的写入与读取）
- `packages/opencode/src/storage/storage.ts`（落盘目录与 JSON 读写）

本项目要求的 `trace` 与 `evidence_pack` 与 OpenCode 的归档机制兼容：

- OpenCode 负责：每一步 tool call 的输入/输出、时间、状态、附件（part）记录
- VulnVersion 负责：把“可证据化引用”汇总成 `trace[].evidence_refs` 与 `evidence_pack[]`，并在 artifacts 中输出稳定 JSON

【与三阶段流程的对应关系（必须）】

- Stage 1：在同一个 session 内，对每个 diff chunk 进行语义角色标注；允许少量 `git_show` 打开上下文窗口作为证据补强
- Stage 2：在同一个或 fork 出来的子 session 内，执行“导航式 RCI 归纳”；使用更大的 tool budget，但仍严格只读
- Stage 3：同样复用 OpenCode Agent 进行逐 tag 判定；允许本地 matcher 做预筛，但最终 verdict 必须由 agent 给出并引用证据

【Agent 核心职责】

1) 接收任务目标（goal）与上下文（CVE 描述、fix commit、chunks 等）
2) 在工具约束下进行多步导航式检索（tool calls），逐步收集证据片段
3) 产出可验证的结构化结果（JSON），并附带可复现实验的轨迹（trace）

【Agent 输入/输出协议（必须）】

- 输入：
  - `goal`: str
  - `repo_path`: str
  - `ref`: str（可为空；Stage 1 可使用 fix commit，Stage 2 可使用 vuln_version/fix_commit）
  - `budget`: {"max_steps": int, "max_tool_calls": int}
  - `context`: dict（由各阶段装配，包含 cve_desc/cwe/chunks 等）
- 输出：
  - `result`: dict（严格符合该阶段 schema）
  - `trace`: list[dict]（每一步包含：step_id、thought_summary、tool_name、tool_args、tool_output_digest、evidence_refs）
  - `evidence_pack`: list[{"ref": str, "source": str, "snippet": str}]（所有被引用证据的原文片段）

【允许的工具集合（必须）】

Agent 只能调用“只读文本工具”，且所有输出必须可记录、可回放：

- OpenCode 内建：`read/grep/glob/list`
- Git 工具库：`git_show/git_grep/git_diff/git_log/list_tags/git_ls_tree/git_cat_file/git_rev_parse/git_merge_base/git_show_ref`
- 可选（仅当必须使用且受控）：`bash`（只读白名单命令；禁用交互编辑器与变更类 git）

不允许：checkout、编译、运行 PoC、调用 CodeQL/AST/CFG/DFG 等分析。

【复用方式（必须）】

- Stage 1：用 OpenCode Agent 执行“chunk 语义角色标注”。允许 agent 为少数不确定 chunks 额外打开对应文件上下文窗口，以提高 role 判定的证据性与稳定性。
- Stage 2：用同一个 OpenCode Agent 执行“导航式 RCI 归纳”。agent 的 tool budget 更大，且必须产出 RCI 的 predicate/guard/self-check，并引用 Stage 1 的相关 chunks 作为证据锚点。

========================
Stage 1：Semantic Patch Aggregation
===================================

【目标】
给定一个 CVE 的修复 commit（fix commit），解析该 commit 修改的所有 diff chunks，并判断这些 chunks 在“漏洞修复语义”中的角色。
注意：本阶段不做“选一个 vuln chunk”，而是识别**与同一漏洞修复相关的语义闭包（hunk set）**。

【输入】

- repo path（可由数据集 `repo` 映射得到，也允许用户显式传入）
- fix commit hash（来自数据集 `fixing_commits` 或用户指定）
- CVE 描述文本（必选；数据集不提供，需要外部获取或用户输入）
- CWE 信息（json数据集中提供）

【处理要求】

1) 使用 `git_diff(fix_commit)`（或等价 git show patch）将 commit 拆分为多个 diff hunks（chunks）
2) 对每个 chunk，提取：
   - file path
   - hunk header
   - removed lines
   - added lines
3) 对每个 chunk，OpenCode Agent 必须先做“上下文自主分析”，再输出角色标注与聚合结论：
   - 使用 hunk header 推断位置与语义单元（函数/方法/宏/结构体等）
   - 在 parent ref（`fix_commit^`）与 fix ref（`fix_commit`）上分别打开必要上下文窗口（使用 `git_show`，窗口大小由 agent 决策并在 trace 中记录）
   - 若 hunk 涉及符号定义/调用点不在同一窗口内，agent 必须导航到定义与关键调用点（`git_grep` → `git_show`）
   - 仅当完成上述上下文确认后，才允许对该 chunk 进行 role 判定与 evidence 引用
4) 统一 OpenCode Agent 对每个 chunk 进行**语义角色标注**（不是打分排序）：
   chunk.role ∈ {
   PRIMARY_FIX,        // 直接修复漏洞的核心语义
   SUPPORTING_FIX,     // 支撑性修复（参数、调用链、类型、边界）
   CONTEXTUAL_CHANGE,  // 语义相关但非必要
   UNRELATED           // 与该 CVE 无关
   }
5) 允许多个 chunk 同时为 PRIMARY_FIX / SUPPORTING_FIX
6) 在所有 chunk 都完成“上下文自主分析 + 角色标注”之后，agent 才能进行 chunk 级语义聚合，输出“RCI-Relevant Hunk Set”（所有非 UNRELATED 的 chunks）与聚合理由

【输出】
artifacts/<cve_id>/patch_semantics.json，包含：

- all_chunks[]
- chunk_roles[]
- rci_relevant_chunks[]（PRIMARY + SUPPORTING）
- excluded_chunks[]（附排除理由）
- aggregation_confidence（0~1）
- dataset_record（可选但建议）：原始数据集 record（repo/fixing_commits/affected_version/CWE），用于评测与复现实验

LLM 输出必须是 JSON，并且：

- 每个 chunk 的 role 必须引用 diff 中的具体代码行作为证据
- 若无法确定角色，必须标记 uncertainty

========================
Stage 2：RCI Generation via Navigation Agent
============================================

【目标】
基于 Stage 1 得到的“漏洞修复语义 hunk set”，生成一个**确信的漏洞存在性定理（RCI / VET）**。
RCI 不是文字总结，而是一个**可执行的、可证伪的漏洞判定规范**。

本阶段不得使用 CodeQL、AST、CFG、DFG 等静态分析工具。
必须采用“导航式 agent”方式（复用统一 OpenCode Agent）：

- agent 通过查看源码文件、函数上下文、调用关系（仅文本）
- 使用只读 Git 工具库（`git_show/git_grep/...`）在 `vuln_version` 上导航与取证；`read/grep/glob/list` 仅用于读取本地 artifacts 与配置（必要时以受控白名单启用 `bash` 的只读命令）
- 逐步理解漏洞的语义结构

【输入】

- repo path
- vuln_version（默认 fix_commit^，也允许用户指定）
- patch_semantics.json（Stage 1 输出）
- CVE 描述文本
- CWE 列表（可选；来自数据集 `CWE`，仅作为先验）
- PoC 文本信息（可选，仅作为触发线索描述，不执行）

【Agent 行为约束（必须）】

1) agent 必须“导航式”地查看源码：
   - 打开受影响文件
   - 查看相关函数
   - 查看被修改变量的定义与使用
   - 查看相关调用点
2) agent 不允许一次性总结，必须：
   - 先定位 anchor（文件/函数/稳定 token）
   - 再分析漏洞前后的语义差异
   - 再归纳漏洞存在的充分/必要条件

【RCI / VET 的定义要求】
生成的 RCI 必须包含以下内容（全部必须）：

1) 基本信息

   - cve_id
   - fix_commit
   - vuln_commit
   - related_chunks（来自 Stage 1）
2) Anchor（跨版本定位锚点）

   - file_paths[]（允许多个）
   - function_names[]
   - stable_tokens[]（API、字段、常量、错误码等）
   - context_window（±N 行）
   - fuzzy_rules（是否忽略变量名/空白/宏）
3) Root Cause（定理核心）

   - summary（一句话，必须引用证据）
   - mechanism_steps[]（触发 → 绕过 → 后果，逐步）
   - vulnerability_type / CWE
4) Vulnerability Predicates（漏洞存在谓词）

   - 一组可执行条件，用 DSL 表示：
     - token_all / token_any
     - regex
     - ordered_tokens
     - proximity（tokens within N lines）
   - 每条谓词必须绑定：
     - scope（anchor window / function）
     - evidence（来自 patch 或源码）
5) Fix Predicates（修复谓词 / 回补等价）

   - 表示“漏洞已被修复”的 token / 结构
   - 必须覆盖等价修复（类型提升、显式检查等）
6) Guards（排除条件）

   - 防止 FP 的条件（例如已有完整检查、不同分支）
   - 若 guard 触发，必须降低置信度或标记 INCONCLUSIVE
7) Trigger Conditions（触发条件）

   - 来自 CVE / PoC 文本的输入约束
   - 格式、字段、路径、调用条件等
8) Patch Logic

   - patch 如何打破漏洞存在谓词
   - 对应 fix_predicates
9) Evidence Pack

   - patch_pre_snippet
   - patch_post_snippet
   - 关键源码片段
   - CVE 描述引用
10) Confidence & Self-Checks

- confidence.total（0~1）
- confidence.components：
  - align_patch_cve
  - discriminative_power（能否区分 pre/post）
  - guard_strength
  - robustness
- self_checks：
  - 在 vuln_commit 上：vuln_predicates 应成立
  - 在 fix_commit 上：fix_predicates 应成立或 vuln_predicates 不成立

【输出】
artifacts/<cve_id>/rci.json

========================
Stage 3：RCI-based Version Verification
=======================================

【目标】
使用 Stage 2 生成的 RCI，对历史版本逐一验证漏洞是否仍然存在。

【输入】

- repo path
- rci.json
- tags（默认扫描全部 tags，支持 --tags-glob / --max-tags）
- --resume（断点续跑）
- ground truth（可选）：来自数据集的 `affected_version`，仅用于评测，不得影响判定逻辑

【处理方式（必须使用 OpenCode Agent）】
Stage 3 同样使用 OpenCode Agent：对每个目标 tag/version，依据 Stage 2 总结的 RCI 进行“逐 tag 自主判定”，并输出置信度与理由（可证据化）。

对每个 tag：

1) 不 checkout 仓库：
   - 使用 `list_tags` 获取候选 tags（或以外部输入提供 target tags）
   - 使用 `git_show/git_grep/git_ls_tree` 在指定 tag 上读取证据
2) 使用 `RCI.anchor`（file_paths/function_names/stable_tokens/context_window）定位候选位置，并在 trace 中记录定位路径
3) 在候选位置执行 `vuln_predicates`，并输出每条谓词的匹配/不匹配证据
4) 执行 `fix_predicates`（若命中则优先 NOT_AFFECTED），并输出证据
5) 执行 `guards`（触发则 INCONCLUSIVE 或显著降低置信度），并输出证据
6) 输出 `verdict ∈ {AFFECTED, NOT_AFFECTED, INCONCLUSIVE}`，同时给出：
   - `confidence`（0~1）
   - `reasoning_summary`（必须引用 evidence refs）
   - `matched_predicates[] / failed_predicates[] / triggered_guards[]`

【输出】
artifacts/<cve_id>/per_tag_verdict.csv / jsonl，包含：

- tag
- verdict
- confidence
- matched_predicates
- evidence_snippets（行号 + 上下文）
- reasoning_summary

【离线评测输出（建议但不强制）】

当提供数据集 `affected_version` 时，额外输出：

- artifacts/<cve_id>/eval.json，包含：
  - gt_affected_tags（来自数据集）
  - scanned_tags（实际扫描到的 tags）
  - unmapped_gt_tags（数据集里存在但仓库无同名 tag 的条目）
  - confusion_matrix（按 tag 粒度：TP/FP/FN/TN/UNK）
  - metrics（precision/recall/F1，`INCONCLUSIVE` 单独统计）

========================
RepoMaster 大仓分析复用设计（必须）
===================================

本项目在“不编译、不使用 CodeQL/CFG/DFG”的前提下，引入 RepoMaster 的核心价值不是“替代证据采集”，而是作为导航加速器与可扩展的仓库索引器，用于：

1) 在大型仓库中快速构建“文件/模块/类/函数/导入关系”的结构化视图，降低 Stage 2 的盲目 grep
2) 计算“关键模块/关键组件”的重要性排序，优先探索最可能承载漏洞语义的区域
3) 生成 LLM 友好的 repo 摘要与重要模块列表，作为导航提示（但不能当作证据）

【RepoMaster 的可复用核心（参考实现位置）】

- 代码树与层次化索引：`RepoMaster-main/src/core/tree_code.py` 的 `GlobalCodeTreeBuilder`
  - 产出：modules/classes/functions/imports/call_graph/key_modules 等结构化数据
- 重要性评分：`RepoMaster-main/src/core/importance_analyzer.py` 的 `ImportanceAnalyzer`
  - 评分因子：imports 关系中心性、使用频次、复杂度、语义关键词、git history 等
- 文档/仓库摘要：`RepoMaster-main/src/core/repo_summary.py`
  - 用于生成“理解仓库所需的最小上下文”提示材料

【与三阶段的集成方式（必须）】

Stage 1（可选加速）

- 输入：fix commit 的 diff 文件列表
- 用法：对被修改文件生成轻量索引与关键符号列表，帮助决定 chunk 的上下文窗口应打开哪些函数/类型定义
- 约束：所有最终 `chunk.role` 证据必须来自 `git_diff/git_show` 的原文片段，索引只提供“去哪看”的提示

Stage 2（强烈建议加速）

- 用法：为导航式 agent 提供“起点建议”（关键模块/关键类/关键函数/导入边），减少无效搜索
- 证据闭环：agent 每次结论仍必须引用 `git_show` 片段；RepoMaster 输出只作为导航 prior，不允许直接引用为证据

Stage 3（可选加速）

- 用法：把 RCI.anchor 的候选 file_paths/function_names/stable_tokens 与 RepoMaster 索引结合，减少 tag 扫描范围
- 约束：tag 级别判定依然仅依赖 `git_show/git_grep/list_tags` 的结果

【产物与缓存（必须）】

为保证可复现实验与跨版本鲁棒性，RepoMaster 的索引产物需要被缓存并可追溯：

- 每个 repo 的索引：`artifacts/<repo_id>/repomaster_index.json`（或等价可读格式）
- 每次运行引用的索引版本：在 `artifacts/<cve_id>/rci.json` 的 metadata 中记录索引 hash/时间戳

========================
工程结构（必须）
================

vulnversion/
  README.md
  environment.yml
  vulnversion/
    cli.py
    config.py
    utils/{subprocess.py,logging.py,paths.py,textnorm.py,jsonschema.py}
    git_ops/{repo.py,show.py,grep.py,diff.py,tags.py,log.py,refs.py}
    opencode/{client.py,agent.py,schemas.py,prompts.py}
    stage1_semantic_aggregation/{extract_chunks.py,annotate_chunks.py,schema.py}
    stage2_rci_navigation/{navigator.py,induce_rci.py,schema.py}
    stage3_verify/{matcher.py,verify_tags.py,schema.py}
tests/

========================
性能与成本控制（必须）
======================

Stage 3 逐 tag 判定可能面临大量 tags，必须实现以下控制策略，避免把“工作量”变成“调用次数”：

1) 本地预筛：
   - 先用 `list_tags` 获取 tags，再用 `git_grep(tag, stable_tokens / anchor hints)` 快速筛出候选 tags
   - 对明显 NOT_AFFECTED 的 tags（强命中 fix_predicates）可直接给出 verdict 并记录证据
2) agent 介入条件：
   - 仅对“本地 matcher 无法强判定”的 tags 调用 OpenCode Agent
   - 对高度相似的 tags（例如同一 commit 指向）允许去重复用结论，但必须记录去重依据（ref 指向）
3) 断点续跑与缓存：
   - `verify-tags` 必须支持 `--resume`，并把每个 tag 的中间证据与 verdict 落盘缓存，避免重复扫描

========================
CLI（必须实现）
===============

1) semantic-aggregate
2) rci-extract
3) verify-tags

【数据集运行入口（必须实现其一）】

为了直接跑论文数据集，CLI 必须支持以下两种调用方式之一（推荐同时支持）：

1) 以“数据集驱动”方式运行单个 CVE：
   - `--dataset` 指定 JSON 路径
   - `--cve-id` 指定 CVE
   - 系统从数据集中自动装配 `repo/fix_commit/CWE/affected_version`
2) 以“显式参数”方式运行单个 CVE：
   - 用户显式传入 `--repo --fix-commit --cve-desc` 等
   - 可选传入 `--gt-affected-tags` 用于评测

========================
Demo（必须）
============

以 FFmpeg CVE-2024-7055 为 demo：

- fix commit: 3faadbe2a27e74ff5bb5f7904ec27bb1f5287dc8
  要求：三阶段跑通，生成 rci.json 与 per_tag_verdict。

========================
开始
====

先输出系统设计与开发计划，再逐文件生成完整代码，最后给出 Ubuntu 22.04 的运行命令示例。
