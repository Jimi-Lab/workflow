# VulnVersion Step1 设计文档：Fix Family 与 Patch Chunk Semantic Filtering

更新时间：2026-05-13

本文档是 VulnVersion Step1 的升级设计文档。Step1 的核心目标不是简单“提取 diff chunk”，而是为 Step2 的 root-cause-level VET 提供干净、可解释、可复现的补丁语义输入。

当前结论：

> Step1 必须存在，而且需要升级。数据集论文和当前 BaseDataOrder.json 都说明，一个 CVE 可能对应多个 fixing commits；即使这些 commits 都属于该 CVE 的修复补丁，commit 内部也可能包含 backport、wrapper、merge、changelog、test/doc、contextual change 或与 root cause 无关的 hunk。Step2 不能直接吃原始 patch。

## 1. Step1 的职责边界

Step1 的职责：

- 解析 CVE 的 fixing commit family。
- 对每个 fix commit 提取 diff、文件、hunk、函数上下文。
- 识别 commit-level 和 chunk-level 的语义角色。
- 去除或降权 wrapper、merge、changelog、test/doc、format-only、contextual change。
- 输出 Step2 可消费的 `patch_semantics.json` 和更细粒度的 `fix_family_semantics.json`。

Step1 不负责：

- 不恢复 affected versions。
- 不做 tag plan。
- 不判断某个 release tag 是否 affected。
- 不输出最终 VET。
- 不读 ground truth affected versions。
- 不把某个 commit 直接等价为 root cause。

## 2. 为什么 Step1 不能删除

How-far-are-we 数据集论文表 II 明确给出 `#CVE` 和 `#Patch`，总计：

| metric | count |
| --- | ---: |
| CVE | 1128 |
| Patch | 1542 |
| Add-only | 329 |
| Del-only | 20 |
| Mixed | 1193 |

这说明补丁数量大于 CVE 数，存在一个 CVE 对应多个 patch/fixing commits 的情况。

论文的错误分析还指出：

- tracing-based 方法经常依赖 deleted/context lines 选 tracing target。
- 多文件/多函数 patch 中常混入 irrelevant hunks。
- 100 个代表性漏洞中，49 个 patch 涉及多函数或多文件，其中 16 个包含 irrelevant hunks。
- 现有方法把所有 patch modifications 当作同等重要，会污染后续 version identification。

因此，即使 dataset 给出了 fixing commits，Step1 仍必须做 semantic filtering。否则 Step2 会把噪声 hunk 当作 root-cause evidence，导致 Step3 的 line score 和 tag judge prompt 被污染。

## 3. 当前目标数据集中的 multi-commit 分布

基于 `E:\AI\Agent\workflow\VulnVersion\DataSet\BaseDataOrder.json` 的本地统计，按每个 CVE flatten 后的唯一 fixing commit 数计算：

| metric | count |
| --- | ---: |
| total CVEs | 1128 |
| single-commit CVEs | 1060 |
| multi-commit CVEs | 68 |
| max commits in one CVE | 15 |
| total unique commit refs after per-CVE flatten | 1345 |

commit 数分布：

| commits/CVE | CVE count |
| ---: | ---: |
| 1 | 1060 |
| 2 | 32 |
| 3 | 3 |
| 4 | 3 |
| 5 | 9 |
| 6 | 9 |
| 7 | 4 |
| 8 | 6 |
| 10 | 1 |
| 15 | 1 |

repo-level 分布：

`patch chunks` 按当前 Step1 的 chunk 定义统计：对每个 fixing commit 执行 git diff，累加 diff hunk 数量。该统计基于 `BaseDataOrder.json` 和本地 9 个 repo，所有 commit diff 均成功读取，`errors=0`。

| repo | CVEs | multi-commit CVEs | patch chunks | distribution |
| --- | ---: | ---: | ---: | --- |
| FFmpeg | 71 | 44 | 552 | `{1:27, 2:13, 3:3, 4:2, 5:7, 6:8, 7:4, 8:6, 15:1}` |
| httpd | 30 | 9 | 408 | `{1:21, 2:7, 4:1, 5:1}` |
| qemu | 57 | 7 | 153 | `{1:50, 2:4, 5:1, 6:1, 10:1}` |
| ImageMagick | 72 | 3 | 202 | `{1:69, 2:3}` |
| openjpeg | 13 | 2 | 19 | `{1:11, 2:2}` |
| wireshark | 50 | 3 | 262 | `{1:47, 2:3}` |
| curl | 68 | 0 | 571 | `{1:68}` |
| linux | 717 | 0 | 2433 | `{1:717}` |
| openssl | 50 | 0 | 183 | `{1:50}` |

总 patch chunks：`4783`。

设计影响：

- Step1 必须优先处理 FFmpeg/httpd/qemu 的 multi-commit semantics。
- Linux 虽然 CVE 数最多，但当前数据集中每个 CVE 都是 single-commit；Linux 的 Step1 难点更偏向 large patch / root-cause extraction，而不是 multi-commit classification。
- curl/openssl 当前没有 multi-commit CVE，不应为了 multi-commit 复杂化其主路径。

## 4. Step1 输入规范

### 4.1 必需输入

| input | source | usage |
| --- | --- | --- |
| `cve_id` | dataset | 标识 CVE |
| `repo` | dataset | 目标项目 |
| `repo_path` | local repo | git diff / show / log |
| `fixing_commits` | dataset | fix family |
| `primary_fix_commit` | dataset normalized | 默认主 commit |
| `cve_description` | dataset / NVD / advisory | 语义先验 |
| `cwe` | dataset | 漏洞类型先验 |
| `cvss_score` | dataset / NVD / advisory | 严重性先验；不能作为代码证据，只能用于报告和 prompt context |
| `cvss_vector` | dataset / NVD / advisory | 攻击向量、权限、交互等先验；可帮助 agent 理解触发条件 |
| `advisory_links` | dataset / local artifact | 可选外部语义来源；必须保存 source ref |
| `issue_or_pr_links` | dataset / local artifact | 可选开发者上下文；不能直接作为 root-cause proof |
| `commit_messages` | git log | patch 意图线索；默认 weak evidence |
| `repository_metadata` | local config | repo 名称、tag prefix、分支模型等上下文 |

当前数据源结论：

- `BaseDataOrder.json` 是正式主数据源，用于读取 CVE、repo、fixing commits、affected versions 等数据集字段。
- `BaseData_nvd.json` 是 Step1/Step2 的 NVD 语义上下文来源，包含 `description`、`cvss2`、`cvss3`、`cvss4`。
- 已核验 `BaseData_nvd.json` 覆盖 1128 个 CVE，其中 `description` 覆盖 1127/1128，`cvss3` 覆盖 1109/1128，`cvss2` 覆盖 368/1128，`cvss4` 覆盖 2/1128。
- 第一版 Step1 以 `BaseData_nvd.json` 为基础语义上下文。若已有 advisory / issue / PR / mailing list / release note，可作为补充 source。

输入完整性要求：

- `cvss_score` 和 `cvss_vector` 应进入 Step1/Step2 的语义上下文，但不能作为 root-cause 代码证据。它们只帮助判断漏洞触发条件、攻击面和影响范围。
- 如果 dataset 或本地 artifact 已提供 advisory、issue、PR、mailing list、release note，应保留原始链接或本地路径，并在输出中记录 `source_ref`。
- 如果缺少 CVSS、advisory 或 issue 文本，Step1 不应阻塞；应在 `step1_quality_report.json` 中记录 `missing_context_fields`。
- CVE description、CWE、CVSS、advisory 只能提供语义先验。最终 root-cause evidence 必须落到具体 file/function/statement/token/guard 上。
- commit message 是弱证据。它可以辅助区分 wrapper、backport、changelog、test/doc commit，但不能单独证明某个 hunk 是漏洞 root cause。
- advisory cache 指本地缓存的外部漏洞说明文本，不是 9 个本地 git repo。它可以作为增强语义上下文的数据源，但不是 Step1 schema 和 deterministic extractor 的前置条件。

### 4.2 禁止输入

Step1 禁止读取：

- affected versions ground truth。
- Step3 tag plan。
- Step3 probe 结果。
- eval metrics。

Step1 可以使用：

| source/tool | 用途 | 注意事项 |
| --- | --- | --- |
| `git diff <commit>^ <commit>` | 提取 files/hunks/added/removed lines | Step1 的基础输入 |
| `git show <patch_commit>` | 查看 commit message、diff、具体文件内容 | commit message 只能作为 weak evidence |
| `git show <commit>:<path>` | 查看 parent/fix 两侧文件上下文 | 用于 root-cause context |
| `git log` | 查看提交历史、rename、相关 issue 文本 | log 不是 root-cause proof |
| `git grep <pattern> <ref>` | 验证 token/function/guard 是否存在 | generic token 需要降权 |
| `git tag --contains <commit>` | 观察 fix commit 被哪些 release tags 包含 | 只能作为 evidence，不做 hard deletion |
| `git describe --contains <commit>` | 找到 commit 附近的 tag / release anchor | 用于理解 patch 所在版本上下文 |
| `git blame` | 定位行级历史来源 | 只作为 root-cause history clue，不直接做 affected boundary |
| `git annotate` | 与 `git blame` 类似，默认参数不同 | 同上 |
| CVE description | 漏洞语义先验 | 需要代码证据支撑 |
| advisory / issue text | 补充 exploit condition 和 affected component | 若来自本地 artifact，必须记录 source ref |

Git 工具的使用边界：

| category | commands | Step1 用途 | 禁止误用 |
| --- | --- | --- | --- |
| 补丁抽取 | `git diff`, `git show` | 提取 changed files、hunks、added/removed lines、commit message | 不能把所有 changed lines 都当 root cause |
| 版本上下文 | `git tag --contains`, `git describe --contains` | 理解 fix commit 所在 release 上下文；给 Step3 提供 evidence hint | 不能 hard 删除包含 fix commit 的 tag 或 line |
| 历史定位 | `git blame`, `git annotate`, `git log` | 找 changed line/function 的历史来源、rename、相关开发者说明 | 不能把 blame/SZZ 结果直接当 affected boundary |
| 快照检查 | `git grep`, `git show <ref>:<path>` | 验证 file/function/token/guard 在某 ref 是否存在 | 不能用普通 token absent 直接判 `NOT_AFFECTED` |

这些命令的共同原则是：Step1 负责生成 evidence，不负责做 affected-version 推断。任何用于 Step3 的 hard certificate 都必须经过 Step2 VET admission 和后续 simulator 验证。

## 5. Step1 输出规范

下一版 Step1 应输出：

```text
fix_family_semantics.json
patch_semantics.json
commit_semantics.jsonl
chunk_semantics.jsonl
step1_quality_report.json
```

### 5.1 `fix_family_semantics.json`

描述 CVE 的整个 fix family。

```json
{
  "schema_version": "fix_family_semantics.v1",
  "cve_id": "",
  "repo": "",
  "primary_fix_commit": "",
  "fix_commits": [],
  "commit_groups": [],
  "family_semantics": "single_fix|or_backport_bundle|component_parallel_fix|possible_composite_fix|mixed_noise",
  "risk_flags": [],
  "confidence": 0.0
}
```

### 5.2 `commit_semantics.jsonl`

每个 commit 一行。

```json
{
  "commit": "",
  "role": "primary_fix|backport_equivalent|component_fix|wrapper_or_merge|test_doc_only|changelog_only|refactor_noise|unknown",
  "patch_type": "add_only|del_only|mixed|empty_or_merge",
  "changed_files": [],
  "source_files": [],
  "test_files": [],
  "doc_files": [],
  "build_files": [],
  "hunk_count": 0,
  "security_relevant_hunk_count": 0,
  "message_signals": [],
  "risk_flags": [],
  "confidence": 0.0
}
```

### 5.3 `chunk_semantics.jsonl`

每个 diff hunk 一行。

```json
{
  "chunk_id": "",
  "commit": "",
  "file_path": "",
  "function_context": "",
  "patch_type": "add_only|del_only|mixed",
  "file_role": "source|test|doc|build|generated|unknown",
  "chunk_role": "primary_fix|supporting_fix|contextual_change|unrelated|test_or_doc|refactor_noise",
  "root_cause_likelihood": 0.0,
  "fix_guard_likelihood": 0.0,
  "vulnerable_sequence_likelihood": 0.0,
  "evidence_refs": [],
  "reasoning_summary": ""
}
```

### 5.4 `patch_semantics.json`

保留现有兼容输出，但字段应升级为从上述 artifacts 派生。

## 6. Commit-level taxonomy

Step1 必须先做 commit-level classification。

| role | 含义 | Step2 使用方式 |
| --- | --- | --- |
| `primary_fix` | 直接修复 root cause 或核心漏洞触发路径 | 高优先级输入 Step2 |
| `backport_equivalent` | 同一修复在不同 branch/release line 的 backport/cherry-pick | OR evidence bundle |
| `component_fix` | 同一 CVE 下不同组件/路径的并行修复 | 分组件输入 Step2 |
| `possible_composite_fix` | 多个 commit 共同完成修复 | risk flag，暂不默认 AND |
| `wrapper_or_merge` | merge/wrapper commit，不含核心代码变化 | 默认不进 root-cause evidence |
| `test_doc_only` | 测试、文档、changelog | 不进 Step2 root-cause evidence |
| `refactor_noise` | 格式化/重构/命名变化 | 降权，仅作 rename/context |
| `unknown` | 证据不足 | 保留但降权 |

默认策略：

```text
multi-commit CVE = OR evidence bundle + noise filtering
```

只有检测到多个 commit 分别修改同一 root-cause path 的不同必要 guard，才标记 `possible_composite_fix`。

## 7. Chunk-level taxonomy

Step1 的核心是 chunk-level filtering。

| role | 含义 | 后续处理 |
| --- | --- | --- |
| `primary_fix` | 直接改变漏洞机制的 hunk | Step2 root-cause candidate |
| `supporting_fix` | 支持核心修复，例如 helper、callsite、type definition | Step2 secondary evidence |
| `contextual_change` | 同 commit 中上下文改动，可能帮助理解但非核心 | prompt context only |
| `unrelated` | 与 CVE 无关 | 排除 |
| `test_or_doc` | 测试、文档、changelog | 排除或低优先级 |
| `refactor_noise` | rename/format/move，无直接安全语义 | 仅用于 rename/move clue |

## 8. Patch type 建模

根据论文统计，补丁类型分布为：

| patch type | count |
| --- | ---: |
| Add-only | 329 |
| Del-only | 20 |
| Mixed | 1193 |

设计要求：

### 8.1 Add-only

Add-only 常表示新增 guard/check/API/validation。

Step1 应抽取：

- added guard condition
- guarded operation nearby
- surrounding vulnerable operation from parent commit
- missing-guard relation

不能只输出 added lines。必须回看 `commit^` 的上下文，找：

```text
old code = dangerous operation exists + guard absent
new code = same operation exists + guard present
```

### 8.2 Del-only

Del-only 可能表示删除 feature、删除 unsafe path、删除 vulnerable code。

Step1 应抽取：

- removed code region
- removed function / branch
- whether removal is feature deletion or refactor
- possible old implementation aliases

不能简单把 deletion 当作 root cause。

### 8.3 Mixed

Mixed 是最大类。

Step1 应同时抽：

- deleted / modified vulnerable sequence
- added fix guard
- changed data/control flow
- unrelated hunks

Mixed patch 中最容易混入 noise，所以必须有 chunk-level role。

## 9. Deterministic extraction layer

Step1 必须先做 deterministic extraction，再让 agent 精炼。

完整 deterministic layer 不是简单执行 `git diff / git show / git log / git grep`。它应负责把原始数据和 git 证据整理成稳定、可追溯、可压缩的 semantic regions。

完整流程：

```text
Input:
  BaseDataOrder.json
  BaseData_nvd.json
  local repo

Deterministic extraction:
  normalize CVE record
  normalize fix commit family
  run git diff/show/log/grep
  extract changed files/hunks/added/removed/context
  classify file role
  classify patch type
  extract guard/check/vulnerable sequence candidates
  extract function/local context
  cluster chunks into semantic regions
  compute region score and risk flags
  generate source_refs

Output to agent:
  compressed semantic region packet
  complete local fix evidence manifest

Artifacts:
  fix_family_semantics.json
  commit_semantics.jsonl
  chunk_semantics.jsonl
  semantic_regions.jsonl
  step1_quality_report.json
  fix_evidence/manifest.json
  fix_evidence/<commit>/show_full_patch.txt
  fix_evidence/<commit>/show_patch_only.txt
  fix_evidence/<commit>/show_numstat.txt
  fix_evidence/<commit>/show_name_status.txt
  fix_evidence/<commit>/show_summary.txt
  fix_evidence/<commit>/diff_tree.txt
  fix_evidence/<commit>/commit_message.txt
```

关键要求：

- `fix family normalization` 必须发生在 diff/chunk 语义判断之前。
- `file role` 和 `patch type` 必须显式输出，不能隐含在 prompt 中。
- `region score` 只用于排序和压缩上下文，不能 hard delete 低分 region。
- 每个可被 Step2 使用的 evidence 都必须带 `source_ref`。
- 每个 fixing commit 的完整 git 证据必须先本地落盘；agent prompt 可以压缩，但不能让完整 patch evidence 消失。
- `source_ref` 必须显式记录 diff line polarity：`added` / `removed` / `context`。Step1 不允许把 added、removed、context 混成无类型 snippet。
- deterministic layer 必须输出 `step1_quality_report.json`，否则无法判断 Step1 是否真正降低了上下文噪声。

### 9.1 Git extraction

对每个 commit：

```text
git diff <commit>^ <commit>
git show <commit>
git show <commit>^:<file>
git log --format
```

抽取：

- file list
- hunk list
- added lines
- removed lines
- hunk header
- parent context
- function context
- file role
- patch type
- commit message

### 9.2 File role classification

规则：

| file pattern | role |
| --- | --- |
| `test/`, `tests/`, `*_test.*`, `fuzz/` | test |
| `doc/`, `docs/`, `.md`, `.rst`, changelog | doc |
| `CMakeLists`, `Makefile`, CI config | build |
| generated markers | generated |
| normal source extension | source |

test/doc/build 默认不能成为 root-cause evidence，但可以作为 supporting context。

### 9.3 Function context extraction

优先使用 lightweight parser；失败时用 hunk header 和 regex fallback。

输出：

- function name
- signature tokens
- surrounding lines
- old/new function body hash
- changed statement sequence

### 9.4 Guard / sequence candidate extraction

对 added lines：

- `if`
- `return error`
- bounds check
- null check
- size/length check
- state validation
- permission/capability check
- API replacement

对 removed/modified lines：

- unsafe API
- memcpy/memmove/strcpy/sprintf 等
- unchecked dereference
- unchecked length
- parser state transition
- allocation/copy mismatch
- integer cast/truncation

## 10. Large patch 处理：Semantic Region Compression

当前不能采用简单 `top-K chunks`。问题不只是 chunk 数量多，而是 large patch 会带来上下文爆炸、语义污染和 agent 调用次数爆炸。固定 top-K 容易漏掉真正 root-cause hunk，尤其是漏洞修复只发生在一个很小 hunk，而其他大 hunk 只是上下文、重构或测试。

Step1 应采用：

```text
large patch
-> deterministic feature extraction
-> file/function/region clustering
-> root-cause candidate scoring
-> compressed semantic region packet
-> agent semantic confirmation
-> Step2 VET evidence
```

### 10.1 Semantic Region 定义

`SemanticRegion` 是 Step1 给 agent 和 Step2 的最小语义单元，不是单个 diff hunk。

`region-level agent refinement` 的含义是：先由 deterministic extractor 把多个相关 diff chunks 按 file/function/local window 聚合成 semantic region，再让 agent 判断 region 的语义角色。它用于替代当前 per-chunk agent 标注，解决 chunk 太多、单 chunk 缺上下文、agent 调用成本高的问题。

典型例子：

```text
一个 commit 在同一函数附近修改 8 个 hunks
-> Step1 聚合为 1 个 semantic region
-> agent 判断该 region 是 primary_root_cause_region / supporting_fix_region / context_region / noise_region
```

一个 region 通常按以下 key 聚合：

```text
repo + cve_id + commit_group + file_path + function_context + nearby_changed_hunks
```

如果函数上下文抽取失败，则降级为：

```text
repo + cve_id + commit_group + file_path + local_line_window
```

### 10.2 Region 必须包含的信息

每个 region 至少包含：

| field | meaning |
| --- | --- |
| `region_id` | 稳定 ID |
| `commits` | 来源 fix commits |
| `file_path` | 文件路径 |
| `function_context` | 函数/方法/符号上下文 |
| `chunk_ids` | region 内包含的 chunk |
| `file_role` | source/test/doc/build/generated/unknown |
| `patch_type` | add_only/del_only/mixed |
| `removed_critical_sequence` | 删除或修改的潜在 vulnerable sequence |
| `added_guard_sequence` | 新增 guard/check/API |
| `nearby_dangerous_operation` | parent/fix 上下文中的危险操作 |
| `data_or_control_flow_hint` | 数据流/控制流线索 |
| `root_cause_score` | deterministic ranking 分数 |
| `evidence_strength` | weak/medium/strong |
| `allowed_downstream_use` | prompt_context/vet_candidate/priority_signal/certificate_candidate |
| `risk_flags` | large_patch/generic_token/agent_failed 等 |
| `source_refs` | 可追溯证据引用 |

### 10.3 Region scoring 只做排序，不做删除

deterministic score 只用于压缩上下文和排序，不允许 hard deletion。

推荐初版评分：

| signal | score |
| --- | ---: |
| source file | +3 |
| test/doc/build/generated | -5 |
| function name or hunk header matches CVE/advisory terms | +2 |
| added guard/check/validation | +3 |
| removed/modified dangerous operation | +3 |
| parent context contains dangerous operation | +2 |
| mixed patch with guard and vulnerable sequence | +2 |
| commit message contains security/CVE/fix keywords | +1 |
| only comments/formatting | -4 |
| generic token only | -2 |
| region too large and unfocused | -1 |

评分输出必须带 `score_reasons`，方便后续审计。

### 10.4 Agent 输入不是完整 diff

agent 不应逐 chunk 阅读完整 large patch。Step1 应给 agent 一个压缩包：

```json
{
  "cve_context": {},
  "commit_group_summary": {},
  "semantic_regions": [
    {
      "region_id": "",
      "file_path": "",
      "function_context": "",
      "patch_type": "",
      "removed_critical_sequence": [],
      "added_guard_sequence": [],
      "nearby_dangerous_operation": [],
      "score_reasons": [],
      "source_refs": []
    }
  ],
  "required_output": "classify each region as primary_fix/supporting_fix/contextual_change/noise/unknown"
}
```

这样做的目标是降低 agent 上下文长度，同时保留所有低分 region 的 artifact，不把它们从系统中删除。

## 11. 可执行实现细则

本节是后续开发 Step1 的工程规格。

### 11.1 新增/扩展模块

建议在 `vulnversion/stage1_semantic_aggregation/` 下新增：

| module | responsibility |
| --- | --- |
| `fix_family.py` | flatten/resolve/dedupe fixing commits，生成 commit groups |
| `file_roles.py` | source/test/doc/build/generated 分类 |
| `chunk_features.py` | hunk-level deterministic features |
| `function_context.py` | function/symbol/local window 抽取 |
| `semantic_regions.py` | chunk -> semantic region 聚合与 scoring |
| `agent_refine_regions.py` | region-level agent semantic confirmation |
| `quality_report.py` | 输出 Step1 质量报告 |

保留兼容：

- 继续写 `patch_semantics.json`。
- 新 artifact 不应破坏旧 Step2/Step3 读取。

### 11.1.1 Artifact 目录规范

Step1 输出统一放在每个 CVE 的 `step1/` 子目录下，避免与 Step2/Step3 artifact 混杂。

推荐目录：

```text
Result/
  <repo>/
    <CVE-ID>/
      step1/
        output/
          fix_family_semantics.json
          commit_semantics.jsonl
          chunk_semantics.jsonl
          semantic_regions.jsonl
          patch_semantics.json
          step1_quality_report.json

        agent_calls/
          <trace_id>.system.txt
          <trace_id>.prompt.txt
          <trace_id>.response.json
          <trace_id>.parsed.json

        trace.jsonl
```

说明：

- `output/` 放 Step1 可被下游消费的稳定 artifact。
- `agent_calls/` 放每次 agent 调用的原始输入/输出，便于 debug 和复现。
- `trace.jsonl` 记录 Step1 的运行事件、packet status、agent status、错误和 resume 信息。
- 旧流程需要的 `patch_semantics.json` 仍写入，但它应从新 artifacts 派生。

### 11.2 Pydantic schema 必须先落地

先实现 schema，再写逻辑。建议新增：

```text
FixFamilySemantics
CommitSemantics
ChunkSemantics
SemanticRegion
RegionRole
Step1QualityReport
EvidenceRef
```

关键枚举：

```text
CommitRole =
  primary_fix
  backport_equivalent
  component_fix
  possible_composite_fix
  wrapper_or_merge
  test_doc_only
  changelog_only
  refactor_noise
  unknown

ChunkRole =
  primary_fix
  supporting_fix
  contextual_change
  unrelated
  test_or_doc
  refactor_noise
  unknown
  unknown_agent_failed

RegionRole =
  primary_root_cause_region
  supporting_fix_region
  context_region
  noise_region
  unknown_region
  unknown_agent_failed

EvidenceStrength =
  weak
  medium
  strong

AllowedDownstreamUse =
  prompt_context
  vet_candidate
  priority_signal
  certificate_candidate
```

强制规则：

- agent 失败时禁止默认 `UNRELATED`。
- 失败应输出 `unknown_agent_failed`，下游只能降权，不能删除。
- `certificate_candidate` 只是候选，不能直接进入 Step3 hard certificate。

### 11.2.1 Schema version 与向后兼容

`schema_version` 是 artifact 的结构版本，不是算法版本。它用于保证下游能判断当前文件是否可读、是否需要 fallback。

规则：

- 每个 JSON/JSONL record 都必须包含 `schema_version`。
- 初版建议：
  - `fix_family_semantics.v1`
  - `commit_semantics.v1`
  - `chunk_semantics.v1`
  - `semantic_region.v1`
  - `step1_quality_report.v1`
  - `patch_semantics.v2`
- `patch_semantics.json` 必须继续写，作为旧 Step2/旧脚本兼容入口。
- 新 Step2 应优先读取 `semantic_regions.jsonl`、`fix_family_semantics.json`、`commit_semantics.jsonl`。
- 如果新 artifact 不存在，新 Step2 可以 fallback 到旧 `patch_semantics.json`，但必须在日志和质量报告中记录 `fallback_to_legacy_patch_semantics`。
- 新字段只能追加，不能静默改变原字段语义。
- enum 变更必须升级 schema version。

### 11.2.2 SourceRef 标准格式

所有可进入 Step2 的 evidence 都必须带 `source_ref`。自然语言 summary 不能单独作为证据。

标准格式：

```json
{
  "ref_id": "src:<cve_id>:<commit>:<file_path>:<kind>:<index>",
  "kind": "git_diff|git_show|git_log|git_grep|nvd_description|cvss|commit_message",
  "commit": "",
  "parent_commit": "",
  "file_path": "",
  "function_context": "",
  "hunk_header": "",
  "line_start": null,
  "line_end": null,
  "snippet": "",
  "snippet_hash": "",
  "strength_hint": "weak|medium|strong"
}
```

要求：

- `ref_id` 在单个 CVE 内必须稳定且唯一。
- `snippet_hash` 用于防止 agent 引用被篡改的片段。
- `kind=nvd_description|cvss|commit_message` 的证据最高只能是 weak，不能单独进入 VET hard certificate。
- code-level evidence 必须来自 `git_diff|git_show|git_grep`。

### 11.3 Deterministic extractor 初版

第一版不接 agent，只跑全量数据集，保证 artifact 稳定。

输入：

```text
cve_id
repo
repo_path
fixing_commits
cve_description
cwe
cvss_score/cvss_vector if available
dataset_record
```

处理：

1. `fix_family.py`
   - resolve SHA。
   - 去重重复 commit。
   - 检测 merge/wrapper/changelog/test-doc。
   - 输出 commit groups。

2. `chunk_features.py`
   - 提取 file/hunk/added/removed。
   - 判断 patch_type。
   - 提取 suspicious APIs、guard/check、critical sequence。
   - 输出 per chunk deterministic features。

3. `file_roles.py`
   - 根据路径/扩展名/生成文件标记分类。

4. `function_context.py`
   - 先用 hunk header。
   - 再用 lightweight parser/regex。
   - 失败则 local window fallback。

5. `semantic_regions.py`
   - 按 file/function/local window 聚合 chunk。
   - 计算 root_cause_score。
   - 输出 compressed region packet。

语言范围：

- 当前 9 个目标 repo 的 CVE 均面向 C/C++ 项目。
- 第一版 Step1 只需要稳定支持 C/C++ 源码上下文抽取。
- `.h / .c / .cc / .cpp / .cxx / .hpp` 等后缀只用于 deterministic 预处理中的 file role/source-file 识别，不用于限制 agent 可读取的源码范围。
- agent 可以按 evidence refs 使用 `git show` 查看必要源码上下文；deterministic 层只负责把明显的 test/doc/build/generated 与 source code 分开，避免无关上下文污染 agent。
- 函数上下文优先使用 hunk header；不足时使用 lightweight regex / brace / local line window fallback。
- 不引入 Tree-sitter 或其他重 parser。Step1 是 agent-driven 语义分析，parser 不是主贡献，也不应成为工程依赖。

输出：

```text
fix_family_semantics.json
commit_semantics.jsonl
chunk_semantics.jsonl
semantic_regions.jsonl
step1_quality_report.json
patch_semantics.json
```

### 11.4 运行模式

Step1 支持两种模式：

| mode | agent | purpose |
| --- | --- | --- |
| `agent_refined` | 启用 | 默认正式模式；deterministic extractor 后执行 region-level agent refinement |
| `deterministic_only` | 禁用 | 消融、调试、批量质量统计；只生成 deterministic artifacts |

默认选择：

```text
agent_refined
```

`deterministic_only` 不是正式最终模式，它用于：

- 全量 1128 CVE 快速跑通 schema 和 extractor。
- 统计 semantic region compression ratio。
- 做 Step1 消融实验。
- 在 agent/backend 不可用时保留可复现 artifact。

### 11.5 Agent refinement 初版

agent 只看 deterministic candidates，不看完整仓库，不自由规划。

输入单位：

```text
一个 CVE 的 compressed semantic region packet
```

agent 输出：

```text
region_id
region_role
root_cause_likelihood
fix_guard_likelihood
vulnerable_sequence_likelihood
evidence_refs
reasoning_summary
risk_flags
```

agent 不允许：

- 使用 affected versions GT。
- 决定 tag plan。
- 判断 release tag affected。
- 编造不存在的 file/function/token。
- 把 generic token 升级成 strong evidence。

### 11.6 Agent 调用失败与 resume 机制

Step1 必须支持 CVE 内 resume，避免 1128 CVE 长跑时因为单次 agent 失败导致整个 CVE 重跑。

规则：

- 每个 agent packet 都有稳定 `packet_id` 和 `trace_id`。
- 每次调用前写入 `trace.jsonl`：`packet_started`。
- 成功后写：
  - `agent_calls/<trace_id>.system.txt`
  - `agent_calls/<trace_id>.prompt.txt`
  - `agent_calls/<trace_id>.response.json`
  - `agent_calls/<trace_id>.parsed.json`
  - `trace.jsonl` 中的 `packet_succeeded`
- 失败/超时后写：
  - `agent_calls/<trace_id>.prompt.txt`
  - `agent_calls/<trace_id>.response.json`，如果有原始响应
  - `trace.jsonl` 中的 `packet_failed`
  - 对应 region 输出 `unknown_agent_failed`
- resume 时：
  - 已有合法 parsed artifact 的 packet 不重复调用。
  - 只重跑失败或缺失 parsed 的 packet。
  - 不能因为 retry 失败把 region 写成 `noise_region`。

### 11.7 Region packet 长度问题

当前不把 packet split 阈值作为 P0 算法设计。原因是过早设置固定长度阈值可能把问题变成新的 top-K/hard-cutoff。

当前策略：

- 第一版先记录 packet 大小、region 数、source_ref 字符数、agent latency。
- 如果 packet 过长导致 agent 失败，先标记 `packet_too_large` 和 `requires_memory_management`。
- 不删除 region，不把超长 packet 中的低分 region hard drop。
- 后续单独设计 memory/context management 机制，再决定是否按 commit group/component/file 进行智能拆包。

最低工程保护：

- 实现层可以设置后端 API 的硬性安全上限，避免一次请求直接崩溃。
- 触发上限时不应截断输出，而应把 packet 标为 failed/deferred，并在 `step1_quality_report.json` 中记录。

### 11.8 Step2 接口规则

Step2 消费 Step1 输出时必须按 evidence strength 分层：

| Step1 输出 | Step2 用途 |
| --- | --- |
| `primary_root_cause_region` + strong/medium evidence | root-cause VET candidate |
| `supporting_fix_region` | supporting evidence |
| `context_region` | prompt context |
| `noise_region` | 默认不消费 |
| `unknown_region` | weak context only |
| `unknown_agent_failed` | weak context + risk flag |

Step2 不得把 Step1 的普通 touched file/token 直接变成 `CERT_ABSENT` 或 `CERT_FIXED`。

## 12. Step1 Agent Prompt 与执行方案

Step1 的 agent 不是自由代码审计 agent，也不是 tag planner。它是 **region-level patch semantic refinement agent**。它只在 deterministic layer 已经完成 evidence extraction、semantic region compression 之后介入，用于确认每个 semantic region 与 CVE root cause / fix semantics 的关系。

### 12.1 Agent 职责边界

agent 应做：

- 判断 semantic region 的语义角色。
- 识别 root-cause relation，例如 missing guard、unsafe operation、bounds check、parser state、integer overflow 等。
- 判断该 region 是否能支撑 Step2 VET。
- 区分 vulnerable sequence、fix guard、supporting context 和 noise。
- 给出 `evidence_refs_used`，引用 deterministic layer 提供的真实代码片段。
- 标记 uncertainty 和 risk flags。

agent 不应做：

- 不读取 affected versions GT。
- 不决定 affected versions。
- 不制定 Step3 tag plan。
- 不判断 release tag 是否 affected。
- 不把 CVSS、commit message、generic token 当作代码 proof。
- 不编造 deterministic packet 中不存在的 file/function/token。
- 不把低证据 region 强行判为 noise；证据不足时必须输出 `unknown_region`。

### 12.2 Prompt 输入包

Step1 agent 的输入不是完整 diff，也不是单个 chunk，而是一个 compressed semantic region packet。

输入结构：

```json
{
  "task": "step1_region_semantic_refinement",
  "schema_version": "step1_agent_region_refinement.v1",
  "cve_context": {
    "cve_id": "",
    "repo": "",
    "description": "",
    "cwe": [],
    "cvss": {
      "cvss2": null,
      "cvss3": [],
      "cvss4": []
    }
  },
  "fix_family_summary": {
    "primary_fix_commit": "",
    "fix_commits": [],
    "commit_messages": [],
    "deterministic_commit_roles": []
  },
  "semantic_regions": [
    {
      "region_id": "",
      "commits": [],
      "file_path": "",
      "function_context": "",
      "patch_type": "add_only|del_only|mixed|empty_or_merge",
      "file_role": "source|test|doc|build|generated|unknown",
      "chunk_ids": [],
      "removed_critical_sequence": [],
      "added_guard_sequence": [],
      "nearby_dangerous_operation": [],
      "data_or_control_flow_hint": [],
      "score_reasons": [],
      "risk_flags": [],
      "source_refs": []
    }
  ]
}
```

输入压缩原则：

- 每个 region 只放必要代码片段，不放完整文件。
- 每个代码片段必须来自 `source_refs`。
- large patch 先由 deterministic layer 聚合为 regions，再给 agent。
- low-score region 仍保留在 artifact 中，但 agent 可优先判断 high/medium-score regions。

### 12.3 Prompt 指令模板

推荐 prompt 主体：

```text
You are a vulnerability patch semantic analyst for VulnVersion Step1.

Goal:
Given deterministic evidence extracted from a CVE fix family, classify each semantic region and decide whether it can support root-cause-level VET construction in Step2.

Strict rules:
1. Do not use affected versions or ground truth.
2. Do not infer affected versions.
3. Do not create a Step3 tag plan.
4. Do not invent files, functions, tokens, or code not present in source_refs.
5. CVE description, CVSS, and commit messages are semantic context only, not code proof.
6. Generic touched tokens are weak evidence only.
7. If evidence is insufficient, output unknown_region.
8. Never downgrade an uncertain security-relevant region to noise_region.

For each semantic region, decide:
- region_role
- evidence_strength
- allowed_downstream_use
- root_cause_relation
- root_cause_likelihood
- fix_guard_likelihood
- vulnerable_sequence_likelihood
- evidence_refs_used
- reasoning_summary
- risk_flags

Output strict JSON only.
```

### 12.4 输出 schema

agent 必须输出：

```json
{
  "schema_version": "step1_agent_region_refinement.v1",
  "cve_id": "",
  "repo": "",
  "region_results": [
    {
      "region_id": "",
      "region_role": "primary_root_cause_region|supporting_fix_region|context_region|noise_region|unknown_region|unknown_agent_failed",
      "evidence_strength": "weak|medium|strong",
      "allowed_downstream_use": [
        "prompt_context",
        "vet_candidate",
        "priority_signal",
        "certificate_candidate"
      ],
      "root_cause_relation": "missing_guard|unsafe_operation|bounds_check|null_check|state_validation|type_confusion|integer_overflow|parser_state|memory_lifetime|permission_check|component_exposure|unknown",
      "root_cause_likelihood": 0.0,
      "fix_guard_likelihood": 0.0,
      "vulnerable_sequence_likelihood": 0.0,
      "vulnerable_sequence": [],
      "fix_guard_sequence": [],
      "evidence_refs_used": [],
      "reasoning_summary": "",
      "risk_flags": []
    }
  ],
  "global_risk_flags": []
}
```

强制校验：

- `region_id` 必须来自输入。
- `evidence_refs_used` 必须来自输入 `source_refs`。
- likelihood 必须在 `[0, 1]`。
- 如果 `evidence_strength=strong`，必须至少有一个 code-level `evidence_refs_used`。
- 如果只有 CVE description / CVSS / commit message 支撑，则最高只能是 `weak`。
- agent 解析失败或超时应写 `unknown_agent_failed`，不能写 `noise_region` 或 `UNRELATED`。

### 12.5 何时开启新 session

Step1 agent session 不应无限复用。建议采用 **per CVE session** 作为默认。

默认策略：

| scenario | session strategy |
| --- | --- |
| 单个 CVE 的普通 patch | 一个 CVE 一个 session |
| multi-commit CVE | 同一个 CVE 仍用一个 session，保持 fix family 上下文一致 |
| region packet 超长 | 当前不做固定阈值拆分；标记 `packet_too_large` / `requires_memory_management`，后续由专门 memory/context 管理机制处理 |
| agent 出错/超时 | 新开 recovery session，只重跑失败的 region packet |
| 不同 CVE | 必须新 session，避免上下文串扰 |
| 不同 repo | 必须新 session |

session 拆分原则：

- 不同 CVE 不共享 session。
- 同一 CVE 内尽量共享 session，以便 agent 理解 fix family。
- 如果 compressed packet 仍过长，第一版不静默截断、不 hard drop region，而是记录失败/延期状态。
- 结果必须写 `session_id`、`packet_id`、`status`，方便恢复和审计。

### 12.6 Agent 工具使用边界

Step1 主读取路径是 Python deterministic layer，不是 agent 自由探索 repo。

允许：

- agent 根据 `source_refs` 请求查看少量 `git show` 上下文。
- agent 使用 evidence refs 核对函数附近代码。
- agent 对 deterministic packet 的判断进行语义 refinement。

不允许：

- agent 自己遍历全仓库。
- agent 自己制定搜索策略替代 deterministic layer。
- agent 使用 Step3 输出或 GT。
- agent 用未记录 source_ref 的代码片段作为证据。

### 12.7 与 Step2 的契约

Step2 只信任经过 Step1 agent refinement 后的结构化字段，不直接信任自然语言 summary。

可进入 Step2 VET candidate 的最低条件：

```text
region_role in {primary_root_cause_region, supporting_fix_region}
and evidence_strength in {medium, strong}
and allowed_downstream_use contains vet_candidate
and evidence_refs_used is not empty
```

不能进入 hard certificate 的情况：

- 只有 CVE description。
- 只有 CVSS。
- 只有 commit message。
- 只有 generic token。
- `unknown_region`。
- `unknown_agent_failed`。
- 没有 code-level source_ref。

### 12.8 Prompt 质量评估

Step1 prompt 是否有效，不能只看单个 agent 输出。必须通过全量或抽样评估：

- region role distribution 是否合理。
- `unknown_region` 是否过高。
- `noise_region` 是否误杀 source-code security region。
- `primary_root_cause_region` 是否有 code-level source_refs。
- region-level agent 调用次数是否明显低于 per-chunk 调用。
- Step2 VET candidate 是否更聚焦。
- Step3 无关 active line 是否下降。

若 prompt 导致大量 `noise_region` 或 `unknown_region`，不能直接接入 Step2 主流程，必须回到 deterministic packet 设计或 prompt 指令修正。

## 13. Step1 与 Step2 的接口

Step2 只应优先消费：

- `primary_fix` chunks
- `supporting_fix` chunks
- `component_fix` commits
- `backport_equivalent` commits 的代表性 evidence

Step2 不应默认消费：

- `test_doc_only`
- `wrapper_or_merge`
- `changelog_only`
- `refactor_noise`
- `unrelated`

如果 Step1 输出 `unknown`，Step2 可保留作为 weak context，但不能作为 strong evidence。

## 14. Step1 质量评估

Step1 不能只看 agent 输出是否合理。必须有数据集级评估。

### 14.1 必做 simulator / audit

建议新增：

```text
E:\AI\Agent\workflow\VulnVersion\tests\simulate_step1_patch_semantics_quality.py
```

输出：

- patch type distribution
- multi-commit taxonomy distribution
- file role distribution
- chunk role distribution
- noisy hunk count
- primary/supporting coverage
- agent error rate
- large patch cases
- per-repo failure cases
- semantic region count distribution
- context compression ratio
- unknown/agent_failed count
- top risky regions per CVE
- dropped-by-hard-delete count，必须恒为 0

### 14.2 与 Step2/Step3 的联合指标

Step1 的好坏最终看：

- Step2 root-cause candidate coverage 是否提高。
- Step2 VET evidence wrong-certificate 是否下降。
- Step3 scheduler 无关 line 是否减少。
- Step3 selected tag judge accuracy 是否提高。

### 14.3 Step1 开发验收 gate

第一阶段验收不是看最终 F1，而是看 Step1 是否稳定地产生高质量输入：

| gate | requirement |
| --- | --- |
| 全量运行 | `BaseDataOrder.json` 1128 CVE 跑完 |
| 无 hard deletion | low-score chunk/region 只能降权，不能消失 |
| agent 失败安全 | agent failure 不得输出 `UNRELATED` |
| schema 稳定 | 所有 artifact 可由 Pydantic 重新读取 |
| 压缩有效 | semantic region 数应显著少于 chunk 数，需要报告 compression ratio |
| 可追溯 | primary/supporting region 必须有 source_refs |
| 下游可用 | Step2 能读取 `semantic_regions.jsonl` 和 `fix_family_semantics.json` |

第一阶段具体阈值：

| metric | threshold |
| --- | --- |
| deterministic 全量完成率 | 1128/1128 CVE |
| schema reload pass rate | 100% |
| hard deletion count | 0 |
| agent failure -> noise/UNRELATED count | 0 |
| missing NVD context | 必须报告，不作为失败 |
| function_context_missing | 必须报告，不作为失败 |
| semantic region compression ratio | 必须报告，第一版不设硬阈值 |
| packet_too_large count | 必须报告，不静默截断 |

第二阶段才看联合指标：

```text
Step1 -> Step2 root_cause_vet -> Step3 scheduler simulator
```

如果 Step3 无关 active line 和 avg probes 没下降，Step1 不能宣称有效。

## 15. 已知风险与降级策略

| 风险 | 降级 |
| --- | --- |
| agent chunk role 判断失败 | 使用 deterministic role + `agent_failed` flag |
| large patch chunk 太多 | semantic region compression，不做固定 top-K hard deletion |
| commit 是 merge/wrapper | 不进 root-cause evidence，仅保留 commit relation |
| patch 是 pure add guard | 回看 parent context，构造 missing-guard candidate |
| patch 是 test/doc | 排除 root-cause evidence |
| multi-commit 分类不确定 | OR evidence bundle + `unknown_multi_commit_semantics` |
| function context 不稳定 | 降级到 file + local token window |
| evidence 过泛 | 标记 `generic_token`，只允许 prompt_context/priority_signal |
| root cause 不在 patch 中 | 标记 `root_cause_not_obvious_in_patch`，请求 Step2/agent 做历史/上下文扩展 |
| advisory 缺失 | 记录 `missing_external_context`，不阻塞 deterministic extraction |

## 16. 已确认决策与仍需后续解决的问题

### 16.1 已确认决策

| item | decision |
| --- | --- |
| 本地代码证据 | 9 个目标 repo 均在本地，有 git 仓库；Step1 可使用本地 git evidence |
| NVD/CVSS 来源 | 使用 `DataSet/BaseData_nvd.json` |
| 外部语义资料 | advisory / issue / PR / mailing list / release note 可作为补充 source，但不作为 schema/extractor 的前置条件 |
| region-level refinement | 用 semantic region 级 agent refinement 替代 per-chunk agent 标注 |
| 语言范围 | 当前全部目标 CVE 面向 C/C++ 项目；后缀只做 source-file 识别，不限制 agent 读源码 |
| parser 方案 | 不引入 Tree-sitter；使用 hunk header + regex/brace/local window fallback + agent 语义判断 |
| root cause 不在 patch 中 | Step1 只标记 `root_cause_not_obvious_in_patch`，不强行恢复 |
| multi-commit 语义 | 默认 OR evidence bundle + noise filtering；少量 possible composite fix 只标 risk flag |

### 16.2 仍需后续解决的问题

以下问题不能在 Step1 中静默假设：

1. **region-level agent 调用策略**  
   是否每个 CVE 都做 agent refinement，还是只对 large/uncertain/high-risk cases 运行，需要先由 `simulate_step1_patch_semantics_quality.py` 统计 region 数和压缩率后再定。当前不建议固定 top-K 或固定调用数。

2. **advisory cache 是否值得建立**  
   当前 schema 和 deterministic extractor 不依赖 advisory cache。若后续发现 NVD description 不足以支撑 root-cause VET，可建立本地 advisory/issue/PR cache 作为增强输入。

3. **函数上下文失败如何降级**  
   不引入 Tree-sitter。若 hunk header / regex / brace window 都失败，Step1 应退化为 file-level semantic region，并把 `function_context_missing` 写入 risk flags。

4. **root cause history search 是否进入 Step2**  
   Step1 不解决真正 VIC/SZZ；如果 root cause 明显不在 patch 中，Step1 只输出 risk flag，后续由 Step2 决定是否做 history search。

## 17. 下一步开发顺序

## 17.0 硬性开发约束：每个功能必须实测

Step1 后续开发必须遵守以下绝对约束：

> 每实现一个功能，必须实际运行对应测试。只有测试结果符合该功能的需求，才可以认为该功能“尚且完成”。

具体要求：

- 新增 schema，必须有 schema round-trip / reload 测试。
- 新增 extractor，必须在真实 repo 和真实 CVE 上运行测试。
- 新增 semantic region compression，必须输出 chunk 数、region 数、compression ratio，并验证没有 hard deletion。
- 新增 agent prompt/refinement，必须保存 prompt、response、parsed，并验证解析结果和 schema。
- 新增 resume 机制，必须模拟 failed packet 后只重跑失败 packet。
- 新增 quality report，必须用 `BaseDataOrder.json` 至少跑代表性样本；正式 gate 必须跑全量 1128 CVE。
- 任何功能没有实际测试结果，不能标记为完成，不能写入“已实现”，只能写为“设计中”或“待验证”。

这是 Step1 开发的最高优先级原则。代码能运行但没有测试证据，不算完成；测试不是补充材料，而是开发完成条件。

### P0：完善 Step1 schema

新增或扩展：

```text
fix_family_semantics.json
commit_semantics.jsonl
chunk_semantics.jsonl
semantic_regions.jsonl
step1_quality_report.json
```

当前实现状态：

- 已实现 Pydantic schema：`EvidenceRef`、`FixFamilySemantics`、`CommitSemantics`、`ChunkSemantics`、`SemanticRegion`、`Step1QualityReport`。
- 已实现 P0 artifact writer：`vulnversion/stage1_semantic_aggregation/artifacts.py::write_step1_p0_artifacts`。
- 已建立 P0 目录结构：`Result/<repo>/<CVE-ID>/step1/output/`、`agent_calls/`、`trace.jsonl`。
- 已输出 P0 基础 artifacts：`fix_family_semantics.json`、`commit_semantics.jsonl`、`chunk_semantics.jsonl`、`semantic_regions.jsonl`、`step1_quality_report.json`、`patch_semantics.json`。
- 当前 P0 不做 git semantic extraction，不调用 agent，只建立稳定 schema 和 artifact contract。

P0 实测结果：

```text
python -m pytest tests/test_step1_p0_artifacts.py -q
2 passed

python -m pytest tests -q
170 passed
```

P0 结论：Schema + Artifact 框架已完成，并且通过实际测试。下一步进入 P1 deterministic extractor。

### P1：写 deterministic extractor

新增：

```text
vulnversion/stage1_semantic_aggregation/fix_family.py
vulnversion/stage1_semantic_aggregation/chunk_features.py
vulnversion/stage1_semantic_aggregation/file_roles.py
vulnversion/stage1_semantic_aggregation/function_context.py
vulnversion/stage1_semantic_aggregation/semantic_regions.py
vulnversion/stage1_semantic_aggregation/quality_report.py
```

当前实现状态：

- 已实现 `file_roles.py`：source/test/doc/build/generated/unknown 分类。
- 已实现 `chunk_features.py`：patch type、guard/check candidates、dangerous sequence candidates、message signals、source_ref 生成。
- 已实现 `function_context.py`：hunk header、C/C++ regex、local line window fallback。
- 已实现 `semantic_regions.py`：按 file/function 聚合 chunk，生成初版 semantic region、score 和 score_reasons。
- 已实现 `deterministic.py::run_step1_deterministic_extractor`：
  - 读取 local git repo。
  - resolve fixing commits。
  - 读取 NVD/CVSS context。
  - 提取 diff hunks、file role、patch type、function/local context、guard/sequence candidates。
  - 输出 `commit_semantics.jsonl`、`chunk_semantics.jsonl`、`semantic_regions.jsonl`、`fix_family_semantics.json`、`step1_quality_report.json`、兼容 `patch_semantics.json`。
  - 不调用 agent。

P1 实测结果：

```text
python -m pytest tests/test_step1_p1_deterministic.py -q
3 passed

python -m pytest tests -q
173 passed
```

P1 测试覆盖：

- 临时真实 git repo 上的 add-only guard patch。
- missing NVD/CVE context 的 quality report 记录。
- `BaseDataOrder.json + BaseData_nvd.json + local FFmpeg repo` 的真实 CVE smoke：`CVE-2022-3965`。

P1 当前限制：

- 只是 deterministic 初版，不做 agent refinement。
- semantic region scoring 是启发式排序，只能用于 priority/context compression，不能 hard deletion。
- function context 失败时降级并记录 risk flag，当前不引入 Tree-sitter。
- 尚未跑全量 1128 CVE 的 quality simulator；这属于 P3。

### P2：改 agent chunk refinement prompt

目标：

- 从“给 chunk 打粗 role”升级为“基于 compressed semantic regions 做语义角色确认”。

P2-A Semantic Region Compression 当前实现状态：

- 已扩展 `ChunkSemantics`：加入 `line_start`、`line_end`、`local_window_key`。
- 已扩展 `SemanticRegion`：加入 `line_start`、`line_end`、`local_window_key`、`compression_input_chunks`、`compression_ratio`。
- 已实现按 `file_path + function_context` 聚合 chunk。
- 当 `function_context` 缺失时，按 `file_path + local_window_key` 聚合，默认 local window size 为 80 行。
- 已实现 region-level `root_cause_score`、`score_reasons` 和 `risk_flags`。
- low-score region 不删除，只降权：
  - `allowed_downstream_use = ["prompt_context"]`
  - `risk_flags` 包含 `low_score_region`
  - 非 source region 标记 `non_source_region`
- function context 缺失的 region 标记 `function_context_missing`。

P2-A 实测结果：

```text
python -m pytest tests/test_step1_p0_artifacts.py tests/test_step1_p1_deterministic.py tests/test_step1_p2_semantic_regions.py -q
8 passed

python -m pytest tests -q
176 passed
```

P2-A 测试覆盖：

- 同一 file/function 下多个 chunks 被压缩为一个 semantic region。
- function context 缺失时，按 local window 聚合，而不是把同文件全部混成一个 region。
- low-score / non-source region 被保留并降权，不做 hard deletion。

P2-A 当前限制：

- 当前只完成 semantic region compression 机制本身。
- 全量 1128 CVE 上的压缩率、large patch 表现、function_context_missing 分布尚未验证；这属于 P3 quality simulator。
- region scoring 仍是启发式初版，只能用于排序和上下文压缩，不能作为 Step2/Step3 hard certificate。

### P3：写 Step1 quality simulator

目标：

- 跑 `BaseDataOrder.json` 全量 1128 CVE。
- 输出 multi-commit taxonomy、noise distribution、large patch cases、semantic region compression ratio。

当前实现状态：

- 已实现 `tests/simulate_step1_patch_semantics_quality.py`。
- 输出目录：`tests/step1_patch_semantics_quality/`。
- 输出文件：
  - `summary.json`
  - `per_repo.json`
  - `per_cve.jsonl`
  - `failure_cases.json`
  - `large_patch_cases.json`
  - `function_context_missing_cases.json`
  - `report.md`

P3 全量实测命令：

```text
python tests/simulate_step1_patch_semantics_quality.py --dataset DataSet/BaseDataOrder.json --nvd DataSet/BaseData_nvd.json --repo-root repo --out tests/step1_patch_semantics_quality
```

P3 全量实测结果：

| metric | value |
| --- | ---: |
| total CVEs | 1128 |
| completed CVEs | 1128 |
| failed CVEs | 0 |
| total chunks | 4783 |
| total semantic regions | 3506 |
| global compression ratio | 0.733013 |
| function_context_missing chunks | 261 |
| function_context_missing ratio | 0.054568 |
| hard deletion count | 0 |
| large patch CVEs，threshold=20 chunks | 38 |

patch type counts，按当前 deterministic chunk 统计：

| patch type | chunks |
| --- | ---: |
| add_only | 1427 |
| del_only | 567 |
| empty_or_merge | 13 |
| mixed | 2776 |

repo-level 结果：

| repo | CVEs | chunks | regions | compression ratio | function missing ratio |
| --- | ---: | ---: | ---: | ---: | ---: |
| FFmpeg | 71 | 552 | 184 | 0.333333 | 0.059783 |
| httpd | 30 | 408 | 264 | 0.647059 | 0.078431 |
| ImageMagick | 72 | 202 | 139 | 0.688119 | 0.059406 |
| wireshark | 50 | 262 | 177 | 0.675573 | 0.026718 |
| qemu | 57 | 153 | 115 | 0.751634 | 0.032680 |
| linux | 717 | 2433 | 1976 | 0.812166 | 0.024661 |
| curl | 68 | 571 | 478 | 0.837128 | 0.161121 |
| openssl | 50 | 183 | 154 | 0.841530 | 0.109290 |
| openjpeg | 13 | 19 | 19 | 1.000000 | 0.000000 |

P3 回归测试结果：

```text
python -m pytest tests/test_step1_quality_simulator.py tests/test_step1_p0_artifacts.py tests/test_step1_p1_deterministic.py tests/test_step1_p2_semantic_regions.py -q
9 passed

python -m pytest tests -q
177 passed
```

P3 结论：

- deterministic layer 稳定性达标：1128/1128 CVE 完成，0 失败。
- P2 semantic region compression 在全量数据上有效，但收益按 repo 差异明显：FFmpeg/httpd 收益较高，openjpeg 无明显压缩空间，linux/curl/openssl 压缩率较弱。
- 当前 function context 缺失总量为 261 chunks，占 5.46%；curl 和 openssl 的缺失比例相对更高，需要后续关注。
- 当前没有 hard deletion，满足 Step1 开发硬约束。
- P3 只验证 deterministic 层稳定性和压缩率，不证明 Step2 VET 或 Step3 probe 已改善；后者需要 P4/P5 联合验证。

### P4：对接 Step2

只有 Step1 输出稳定后，Step2 才开始生成 root-cause-level VET。

### P4-A：Agent Region Refinement

当前实现状态：

- 已实现 `vulnversion/stage1_semantic_aggregation/agent_refine_regions.py`。
- 已实现 region-level prompt packet 构造：
  - 输入 `semantic_regions.jsonl`。
  - 构造 compressed semantic region packet。
  - 调用 `AgentRuntime.create_readonly_session()`，默认 per-CVE session。
  - 调用 `AgentRuntime.run_json()` 输出 region refinement JSON。
- 已实现 agent call artifacts：
  - `step1/agent_calls/<trace_id>.system.txt`
  - `step1/agent_calls/<trace_id>.prompt.txt`
  - `step1/agent_calls/<trace_id>.response.json`
  - `step1/agent_calls/<trace_id>.parsed.json`
- 已实现 `trace.jsonl` 事件：
  - `packet_started`
  - `packet_succeeded`
  - `packet_failed`
  - `packet_resumed`
- 已实现 `region_refinements.jsonl` 输出。
- 已实现 resume：
  - 若 parsed artifact 已存在，跳过 agent 调用。
  - 只复用已有合法 parsed packet。
- 已实现失败降级：
  - agent 异常/超时/解析失败时，每个 region 输出 `unknown_agent_failed`。
  - 不会把失败 region 写成 `noise_region` 或 `UNRELATED`。
- 已实现真实后端稳健性修正：
  - 对 agent 输出的非法 `allowed_downstream_use` 做安全归一化，例如 `step2_direct_input -> vet_candidate`。
  - 对非法 literal 字段降级为安全默认值，避免一个弱 schema 错误导致整包失败。
- P4 prompt 明确要求只输出一个 JSON object。
- Region packet 不再直接传完整 `SemanticRegion.model_dump()`，而是传压缩后的 `source_refs_sample`。
- 已修正：P4 不得只依赖 `source_refs_sample`。Step1 必须先写入完整 `fix_evidence` artifact，prompt 中必须携带 `fix_commit_evidence` manifest 和完整 patch 路径。
- 已修正：P4 在 `enable_git_tools=True` 时允许 agent 使用受控只读 git/bash 能力。agent 可以查看完整 commit patch、文件、函数、历史，但不能修改 repo、删除文件、切换分支、搜索 affected versions 或创建 tag plan。

P4-A 实测结果：

```text
python -m pytest tests/test_step1_p4_agent_refinement.py tests/test_step1_p5_step2_adapter.py tests/test_step1_p5_joint_validation.py -q
12 passed

python -m pytest tests -q
189 passed
```

P4-A 测试覆盖：

- fake AgentRuntime 正常返回时，写入 `region_refinements.jsonl` 和 agent call artifacts。
- 默认 per-CVE session 被创建，metadata 包含 `stage=stage1` 和 `task_type=region_refinement`。
- resume 模式下已有 parsed packet 不重复调用 agent。
- agent failure 时 region role 变为 `unknown_agent_failed`，并记录 `packet_failed`。
- 非法 `allowed_downstream_use` 不会导致整包失败，会被归一化到安全 enum。
- Prompt 使用压缩后的 region packet，但必须携带完整 `fix_commit_evidence` 路径，避免关键 diff 信息被 sample 丢失。

P4-A 真实 OpenCode 小样本验证：

后端环境：

```json
{
  "health": {"healthy": true, "version": "1.2.26"},
  "provider_id": "deepseek",
  "model_id": "deepseek-v4-flash"
}
```

第一轮真实 smoke 暴露的问题：

```text
selected_cves = [CVE-2022-3965, CVE-2020-8169, CVE-2020-15389]
completed_cves = 3
agent_success_cves = 1
agent_failed_cves = 2
avg_latency_s = 132.354
```

失败原因：

- `CVE-2020-8169`：agent 输出非法 `allowed_downstream_use=step2_direct_input`，schema 过严导致整包失败。
- `CVE-2020-15389`：OpenCode 返回文本未形成可解析 JSON。

修正后第二轮真实 smoke：

```text
python tests/validate_step1_p4_opencode.py --dataset DataSet/BaseDataOrder.json --nvd DataSet/BaseData_nvd.json --repo-root repo --out tests/step1_p4_opencode_validation_compressed --timeout-s 900 --no-resume

selected_cves = [CVE-2022-3965, CVE-2020-8169, CVE-2020-15389]
completed_cves = 3
failed_cves = 0
agent_success_cves = 3
agent_failed_cves = 0
avg_latency_s = 79.063
avg_regions = 2.333
region_role_counts = {
  "noise_region": 2,
  "primary_root_cause_region": 2,
  "supporting_fix_region": 3
}
```

重要修复验证：

- `CVE-2022-3965` 在未压缩 packet 时 900s timeout。
- 压缩 packet 后单独重跑：

```text
completed_cves = 1
agent_success_cves = 1
agent_failed_cves = 0
avg_latency_s = 70.422
region_role_counts = {
  "primary_root_cause_region": 1,
  "supporting_fix_region": 1
}
```

P4-A 当前限制：

- 3-CVE smoke 已通过，但更大样本仍需要 A/B 验证。
- 尚未证明 P4 refinement 能提升 Step2 VET 质量或降低 Step3 probes；这需要 Step2/Step3 联合 simulator。

### P4-B：Packet-only vs Packet + Read-only Git Tools A/B

问题背景：

- `packet-only` 依赖 Python deterministic layer 提供的 compressed evidence packet。
- `packet + read-only git tools` 允许 agent 在 P4 refinement 中使用只读 `git_show` / `git_grep` / `git_log` / `git_diff`。
- 直觉上，git tools 可能让 agent 补足 packet 没覆盖的信息；但也可能导致 agent broad exploration、耗时上升、JSON 输出不稳定。

实现状态：

- `refine_regions_with_agent(..., enable_git_tools=False)` 默认仍为 packet-only。
- `enable_git_tools=True` 时启用：
  - `git_show=True`
  - `git_grep=True`
  - `git_log=True`
  - `git_diff=True`
  - `bash=True`
- P4-B prompt 明确限制：
  - 只能围绕 packet 和 `fix_evidence` manifest 中列出的 commits、files、functions、snippets 查询。
  - 如果 `source_refs_sample` 不完整，必须优先查看 `fix_evidence/<commit>/show_full_patch.txt` 或使用只读 git 命令核对完整 patch。
  - 不允许搜索 affected versions。
  - 不允许创建 tag plan。
  - 新增 git evidence 必须写入 `evidence_refs_used` 或 reasoning。

3-CVE A/B smoke：

```text
sample = [CVE-2022-3965, CVE-2020-8169, CVE-2020-15389]

packet-only:
  agent_success_cves = 3/3
  agent_failed_cves = 0
  avg_latency_s = 87.964

packet + read-only git tools:
  agent_success_cves = 3/3
  agent_failed_cves = 0
  avg_latency_s = 44.000
```

3-CVE 结论：git-tools 版本在小样本上更快，且没有降低成功率。

18-CVE A/B 扩展验证：

样本选择：

```text
每个 repo 取 2 个 CVE，共 18 个 CVE：
FFmpeg, ImageMagick, curl, httpd, linux, openjpeg, openssl, qemu, wireshark
```

命令：

```text
python tests/validate_step1_p4_opencode.py --dataset DataSet/BaseDataOrder.json --nvd DataSet/BaseData_nvd.json --repo-root repo --out tests/step1_p4_ab_packet_only_18cve --timeout-s 900 --no-resume --cves <18-cve-list>

python tests/validate_step1_p4_opencode.py --dataset DataSet/BaseDataOrder.json --nvd DataSet/BaseData_nvd.json --repo-root repo --out tests/step1_p4_ab_git_tools_18cve --timeout-s 900 --no-resume --enable-git-tools --cves <18-cve-list>
```

结果：

| variant | success CVEs | failed CVEs | avg latency s | unknown failed regions |
| --- | ---: | ---: | ---: | ---: |
| packet-only | 16/18 | 2 | 96.458 | 3 |
| packet + read-only git tools | 16/18 | 2 | 154.278 | 13 |

逐 CVE 差异摘要：

- git-tools 更快：7/18。
- git-tools 更慢：11/18。
- git-tools 成功率提升：1 个 CVE。
- git-tools 成功率回退：1 个 CVE。
- 明显回退案例：`httpd CVE-2022-30522`
  - packet-only 成功，48.5s。
  - git-tools 900.375s timeout，11 个 regions 全部 `unknown_agent_failed`。
- 明显提升案例：`linux CVE-2022-0185`
  - packet-only 900.282s timeout。
  - git-tools 43.204s 成功。

P4-B 结论：

- 当前证据不支持把 read-only git tools 无条件设为默认。
- 3-CVE smoke 支持 git-tools，但 18-CVE 扩展样本显示它会显著增加平均耗时和 failed regions。
- 更合理的策略是：
  - 默认使用 packet-only。
  - 当 packet-only 出现 timeout、unknown_agent_failed、function_context_missing 或 evidence 不足时，再触发 git-tools 二次 refinement。
  - git-tools 应作为 fallback / selective refinement，而不是主路径。

P4-B artifact：

```text
tests/step1_p4_ab_packet_only_3cve/
tests/step1_p4_ab_git_tools_3cve/
tests/step1_p4_ab_packet_only_18cve/
tests/step1_p4_ab_git_tools_18cve/
tests/step1_p4_ab_compare_18cve/
```

### P4-C：完整 fix evidence 与只读工具修正

问题来源：

- 在 `curl/CVE-2024-8096` 中，官方 fix commit `aeb1a281cab13c7ba791cb104e556b20e713941f` 修改 `lib/vtls/gtls.c`，实际 patch 为 `73 insertions / 73 deletions`。
- 旧版 P4 prompt 只传 `source_refs_sample`，主 region 只暴露 5 条 snippet，无法让 agent 完整理解 OCSP stapling 修复语义。
- 这说明 Step1 不能只依赖 Python 抽样后的 packet。即使 packet 是压缩后的，也必须保留完整 fix commit evidence，并允许 agent 在受控只读权限下自行核对 git 证据。

已修正的实现：

- `step1_paths()` 新增 `step1/fix_evidence/` 与 `fix_evidence/manifest.json`。
- P1 deterministic extractor 对每个 fixing commit 写入完整本地证据：
  - `show_full_patch.txt`
  - `show_patch_only.txt`
  - `show_numstat.txt`
  - `show_name_status.txt`
  - `show_summary.txt`
  - `diff_tree.txt`
  - `commit_message.txt`
- P4 prompt 新增 `fix_commit_evidence` 字段，指向完整证据 manifest 和每个 evidence 文件路径。
- `enable_git_tools=True` 时，P4 允许 `git_show/git_grep/git_log/git_diff/bash`，但 system prompt 明确限制为只读核验，不允许修改 repo、删除文件、切换分支、安装依赖、搜索 affected versions 或创建 tag plan。

实测：

```text
python -m pytest tests/test_step1_p1_deterministic.py tests/test_step1_p4_agent_refinement.py tests/test_opencode_permissions.py -q
10 passed

curl/CVE-2024-8096 real regression:
manifest = tests/step1_fix_evidence_regression/curl/CVE-2024-8096/step1/fix_evidence/manifest.json
show_full_patch.txt lines = 200
patch_has_ocsp_checked = True
patch_has_no_status_request = True
prompt_has_fix_commit_evidence = True
prompt_has_show_full_patch = True
tools = {git_show=True, git_grep=True, git_log=True, git_diff=True, bash=True}
```

当前仍未完成：

- 已修正 `source_refs` polarity schema：`EvidenceRef` 新增 `change_type`、`old_line_no`、`new_line_no`。
- 已修正 diff parser：每个 hunk 现在保留 ordered `lines`，每行显式标注 `added` / `removed` / `context`。
- 已修正 sequence 聚合：`added_guard_sequence` 只来自 `change_type=added` 的 guard candidate；`removed_critical_sequence` 只来自 `change_type=removed` 的 dangerous candidate；context 只进入 `nearby_dangerous_operation`。
- 已收紧 dangerous regex，避免把普通指针声明如 `const char *x;` 当作 vulnerable sequence。

实测：

```text
python -m pytest tests/test_step1_p1_deterministic.py tests/test_step1_p4_agent_refinement.py -q
10 passed

curl/CVE-2024-8096 polarity regression:
source_ref_change_counts = {context: 2, removed: 23, added: 25}
removed_seq_count = 0
added_guard_count = 20
same_sequences = False
```

当前仍未完成：

- 还没有完整 edit-block schema。当前已经有 line-level polarity，但还没有把连续 added/removed/context 聚合成稳定 edit block。
- `removed_critical_sequence` 现在更保守，可能为空；这比污染更安全，但后续 Step2 VET 需要结合完整 `fix_evidence` 和 agent refinement 恢复 root-cause semantics。

### P5：Step2 对接与联合验证

P5 的目标不是直接宣称 Step3 probes 已下降，而是先打通一个可验证的接口：

```text
Step1 semantic_regions.jsonl + fix_family_semantics.json
-> Step2 RootCauseVet seed
-> Step2 RCI/VET prompt context
-> 后续 Step3 scheduler simulator / 主流程消费
```

当前实现状态：

- 已新增 `vulnversion/stage2_rci_navigation/step1_adapter.py`。
- `load_step1_vet_seed()` 可读取：
  - `step1/output/fix_family_semantics.json`
  - `step1/output/semantic_regions.jsonl`
  - 可选 `step1/output/region_refinements.jsonl`
- `build_root_cause_vet_from_step1()` 将 Step1 产物转换为 Step2 的 `RootCauseVet`。
- `run_stage2()` 在 CVE 结果目录存在 `step1/output` 时，会自动生成 `step1_vet_seed.json` 并传入 `induce_rci()`。
- `induce_rci()` 的 no-agent fallback 会保留 `step1_vet_seed`，并写入 `metadata.step1_vet_seed_consumed=true`。

安全边界：

- 默认只把 Step1 evidence 作为 `priority` / `prompt_context`。
- 默认不生成 `certificate_candidate`。
- 即使 `region_refinements.jsonl` 中 evidence 为 strong，也不会自动进入 certificate。
- 只有显式启用 `allow_step1_certificates=True`，且 Step1 refinement 明确带 `certificate_candidate`，才允许生成 certificate candidate。
- 这保证 P5 不会把普通 touched file、普通 function、普通 token 直接变成 `CERT_ABSENT` / `CERT_FIXED`。

P5 新增测试：

```text
tests/test_step1_p5_step2_adapter.py
tests/test_step1_p5_joint_validation.py
tests/simulate_step1_step2_joint_validation.py
```

P5 实测结果：

```text
python -m pytest tests/test_step1_p5_step2_adapter.py tests/test_step1_p5_joint_validation.py -q
7 passed

python -m pytest tests/test_step1_p0_artifacts.py tests/test_step1_p1_deterministic.py tests/test_step1_p2_semantic_regions.py tests/test_step1_p4_agent_refinement.py tests/test_step1_quality_simulator.py tests/test_step1_p5_step2_adapter.py tests/test_step1_p5_joint_validation.py tests/test_vet_schema.py -q
22 passed

python -m pytest tests -q
187 passed
```

P5 全量联合验证命令：

```text
python tests/simulate_step1_step2_joint_validation.py --dataset DataSet/BaseDataOrder.json --nvd DataSet/BaseData_nvd.json --repo-root repo --out tests/step1_step2_joint_validation
```

P5 全量联合验证结果：

```json
{
  "total_cves": 1128,
  "completed_cves": 1128,
  "failed_cves": 0,
  "cves_with_priority_patterns": 1126,
  "priority_pattern_coverage": 0.998227,
  "total_priority_patterns": 12729,
  "avg_priority_patterns_per_cve": 11.285,
  "pattern_counts": {
    "fix_guards": 3782,
    "root_cause_files": 1935,
    "root_cause_functions": 3283,
    "vulnerable_sequences": 3729
  },
  "total_certificate_candidates": 0,
  "wrong_certificate_risk_from_adapter": 0,
  "stage3_probe_reduction_measured": false
}
```

P5 当前结论：

- Step1 -> Step2 的结构化接口已经可运行，并在 1128 CVE 上稳定通过。
- Step1 产物可以为 1126/1128 CVE 提供 Step2 priority/prompt-context VET seed。
- 当前 adapter 不引入 certificate candidate，因此不会新增 wrong-certificate 风险。
- 但当前仍未证明 Step3 `irrelevant active lines` 或 `avg probes` 已下降。原因是 Step3 scheduler 尚未消费 `RootCauseVet` priority patterns。
- 下一步必须修改 Step3 的 VET Evidence Graph / scheduler simulator，让 `RootCauseVet` 真实参与 line priority / activation order；只有 simulator 证明有效后，才能接入 Step3 主流程。

## 18. 当前设计判断

Step1 的论文价值不是“调用 agent 看 diff”，而是：

> multi-commit fix family normalization + semantic region compression + patch chunk semantic filtering + root-cause evidence preparation。

这一步做不好，Step2 会从一开始就吃到噪声，后续 VET、line score、tag judge prompt 都会被污染。
