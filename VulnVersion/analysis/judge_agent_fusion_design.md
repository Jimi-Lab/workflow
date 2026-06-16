# Judge Agent Fusion Design for VulnVersion

## 1. 目标

当前数据集 `DataSet/BaseDataOrder.json` 只提供 `affected_version`、`fixing_commits`、`repo` 和 `CWE`，不提供人工标注 BIC。因此，VulnVersion 的核心问题不是简单复现某个 SZZ 工具，而是把：

```text
FIC patch
-> root cause
-> top-k pre-fix vulnerable anchors
-> BIC candidates
-> BIC/FIC to affected versions
```

做成一个可审计、可消融、可解释的 pipeline。

本设计聚焦 Judge Agent：它不再直接判断某个 tag 是否 affected，而是先承担 BIC 边界判定任务。现有 `stage3_verify` 的 tag-level judge 仍然有价值，但它应该位于 BIC/FIC 转换后的校验层，而不是替代 BIC 边界判断。

## 2. 来自 Agentic-SZZ 与 MAS-SZZ 的实验结论

30 CVE pilot 的关键结果：

| 方法 | BIC coverage | Topology Micro-F1 | Latest-FIC Micro-F1 |
|---|---:|---:|---:|
| Agentic-SZZ | 83.33% | 39.21% | 44.69% |
| MAS-SZZ | 96.67% | 71.42% | 85.31% |

这个差距不是因为 MAS-SZZ 的整体架构更强，而是因为它更贴近本任务的关键链路：

```text
root cause -> semantic vulnerable statement -> blame
```

Agentic-SZZ 值得学习的是：

1. 结构化历史候选空间。
2. 受限工具搜索。
3. 可审计 trajectory。
4. direct blame、blame ancestor、BFC ancestor 的统一候选池。

Agentic-SZZ 不应照搬的是：

1. add-only 只取新增行附近上下文。
2. 新文件或无 deleted line 时容易空结果。
3. 文件历史扩展范围过宽，token 成本高。
4. TKG agent 失败后可能直接返回空 BIC。

MAS-SZZ 值得学习的是：

1. 先解释 root cause，再定位 pre-fix vulnerable statements。
2. 一个 CVE 允许多个 statement 和多个 BIC。
3. add-only 时从新增 guard 反推被保护的旧代码。
4. hunk grouping 和 root-cause relevance filtering。

MAS-SZZ 不应照搬的是：

1. reviewer 29/29 全通过，缺少拒绝能力。
2. `exists=False` 时仍可能返回当前 blame commit。
3. 达到 trace depth 上限时不能伪装成找到 BIC。
4. fallback 容易选中错误字符串表、生成文件、文档、测试。

## 3. 当前 VulnVersion 的工程边界

当前已有两类相关模块：

1. `vulnversion/vulngraph_judge`
   - 已有 `GraphNode`、`GraphEdge`、`allowed_use`、packet 提取。
   - 当前节点类型包含 `RootCauseTheorem`、`VulnerablePredicate`、`FixPredicate`、`Anchor` 等。
   - 适合作为新的 anchor 和 BIC 判定事件存储层。

2. `vulnversion/stage3_verify`
   - 已有 tag-level `TagVerdict`。
   - `verify_tags.py` 的 v1 prompt 已经是 target-tag theorem judge。
   - `line_scheduler.py` 已经按 release line 做 staged scheduling。

需要补的不是另一个 tag judge，而是 BIC-oriented Judge Agent：

```text
RootCauseAnchorJudge
-> BlameCandidateRetriever
-> BICBoundaryJudge
-> BICClusterResolver
-> BranchAwareVersionConverter
```

## 4. 核心设计：Root Cause 阶段输出 top-k anchors

Root Cause Agent 不应只输出一段自然语言 summary，而应输出 top-k 可 blame 的 pre-fix anchors。

建议命名：

```text
TopKPreFixAnchors
```

每个 anchor 是一个“漏洞语义锚点”，不是普通行号。

```json
{
  "anchor_id": "CVE-XXXX-YYYY:A1",
  "rank": 1,
  "repo": "curl",
  "fix_commit": "<fic>",
  "parent_commit": "<fic_parent>",
  "file": "lib/example.c",
  "line_range_in_parent": [120, 128],
  "symbol": "example_func",
  "role": "missing_guard_target",
  "anchor_kind": "pre_fix_existing_code",
  "root_cause_link": "新增 bounds check 保护该长度变量在旧版本中的危险使用",
  "patch_link": {
    "hunk_id": "H1",
    "change_type": "add_guard",
    "fix_lines": [55, 61]
  },
  "blame_strategy": [
    "semantic_anchor_blame",
    "function_history",
    "rename_aware_blame"
  ],
  "confidence": 0.82,
  "risk_flags": ["add_only_case"]
}
```

Anchor 必须满足：

1. 位于 `C_fix^1`，也就是修复前版本。
2. 能解释 root cause 的某一环。
3. 能通过 `git blame`、函数历史或路径历史继续追踪。
4. 不是单纯的新增 guard 本身。
5. 不是 generated file、error registry、test fixture、文档，除非 root cause 明确发生在这些文件中。

## 5. top-k 不是 top1：为什么必须保留多 anchor

MAS-SZZ 的多 BIC union 在 pilot 中优于 top1，说明 affected-version 任务需要表达：

```text
one root cause -> multiple semantic anchors -> multiple BICs
```

Root Cause Agent 应输出 `K=5~10` 个 anchors，并做 diversity selection，而不是只按分数排序。

推荐保留规则：

1. 每个 root-cause role 至少保留一个：
   - source
   - propagation
   - sink
   - missing_guard_target
   - state_definition
   - callback_registration
   - recursion_entry
2. 每个与 root cause 相关 hunk 至少保留一个。
3. 多文件补丁中，每个 root-cause file 至少保留一个。
4. add-only case 必须至少包含一个 `protected_old_use` anchor。
5. fallback anchors 必须低置信度标记，不得和 direct semantic anchors 等价。

建议打分：

```text
score =
  0.30 * root_cause_relevance
+ 0.20 * parent_existence
+ 0.15 * patch_link_strength
+ 0.15 * blameability
+ 0.10 * file_role_quality
+ 0.10 * diversity_bonus
- penalties
```

常见 penalty：

```text
generated_file
error_string_table
test_or_doc_only
line_not_in_parent
only_nearby_context
symbol_not_linked_to_root_cause
large_rename_uncertainty
```

## 6. Judge Agent 分层

### 6.1 Anchor Admission Judge

输入：Root Cause Agent 的 top-k anchors。

目标：判断 anchor 是否值得进入 blame。

输出状态：

```text
ANCHOR_ACCEPT
ANCHOR_REJECT_NOT_IN_PARENT
ANCHOR_REJECT_NOT_ROOT_CAUSE_RELATED
ANCHOR_REJECT_GENERATED_OR_DOC
ANCHOR_REJECT_UNBLAMEABLE
ANCHOR_NEEDS_RELOCATION
ANCHOR_INSUFFICIENT_EVIDENCE
```

它只做 admission，不决定 BIC。

### 6.2 Blame Candidate Retriever

这是确定性 Git 工具层，不由 LLM 自由发挥。

候选来源：

```text
direct_deleted_blame
semantic_anchor_blame
function_history
rename_history
callgraph_predecessor
blame_ancestor
bfc_ancestor
patch_series_ancestor
branch_equivalent_introduction
```

每个候选必须记录 provenance：

```json
{
  "candidate_commit": "<sha>",
  "source_anchor_id": "CVE-XXXX:A1",
  "retrieval_method": "semantic_anchor_blame",
  "file_at_candidate": "lib/example.c",
  "line_range_at_candidate": [98, 103],
  "rename_trace": [],
  "score_before_judge": 0.74
}
```

### 6.3 BIC Boundary Judge

这是最关键的 Judge Agent。

输入：

```text
anchor
candidate C_j
parent C_j^1
root cause theorem
candidate diff
candidate-side code slice
parent-side code slice
```

判定规则：

```text
ACCEPT_BIC only if:
  bug(C_j) = true
  AND bug(C_j^1) = false
  AND transition is relevant to the same root cause
```

必须禁止以下 MAS-SZZ 式错误：

```text
if bug(C_j) = false:
  never return C_j as BIC

if max_depth reached:
  return CENSORED_DEPTH, not ACCEPT_BIC
```

输出：

```json
{
  "candidate_commit": "<sha>",
  "parent_commit": "<sha>^",
  "decision": "ACCEPT_BIC",
  "bug_in_candidate": true,
  "bug_in_parent": false,
  "transition_type": "introduced_missing_bounds_check",
  "matched_anchor_ids": ["CVE-XXXX:A1"],
  "evidence": [
    {
      "ref": "<sha>:lib/example.c:98",
      "source": "git_show",
      "snippet": "actual code snippet"
    }
  ],
  "rejection_reason": null,
  "confidence": 0.86
}
```

Reject 状态：

```text
REJECT_NO_BUG_IN_CANDIDATE
REJECT_BUG_ALREADY_IN_PARENT
REJECT_ROOT_CAUSE_MISMATCH
REJECT_FIX_SERIES_COMMIT
REJECT_REFACTOR_ONLY
REJECT_TEST_DOC_GENERATED_ONLY
REJECT_UNRELATED_MESSAGE_STRING
CENSORED_DEPTH
CENSORED_TOKEN
INSUFFICIENT_EVIDENCE
```

### 6.4 BIC Cluster Resolver

多个 anchors 和多个候选可能指向同一 root cause 的不同历史位置。Resolver 不应强行 top1。

输出：

```json
{
  "bic_cluster_id": "CVE-XXXX:BIC_CLUSTER_1",
  "accepted_bics": ["<sha1>", "<sha2>"],
  "rejected_candidates": [],
  "cluster_role": "same_root_cause_multiple_locations",
  "requires_branch_equivalence": true,
  "confidence": 0.78
}
```

## 7. Add-only 专用路径

add-only 的核心不是 blame 新增行。

流程：

```text
新增语句分类
-> 提取被保护对象
-> 在 C_fix^1 中找旧使用点
-> 生成 protected_old_use anchors
-> blame old-use anchors
```

新增语句类型：

```text
guard
bounds_check
null_check
state_initialization
callback_registration
cleanup
lock
depth_limit
type_check
permission_check
```

Root Cause Agent 对 add-only 必须回答：

1. 新增检查保护的变量或状态是什么？
2. 修复前这些变量或状态在哪里被使用？
3. 使用点如何通向 crash、overflow、UAF、OOB、infinite recursion 或 authorization bypass？
4. 哪些修复新增行只是防御，不应作为 blame anchor？

Judge Agent 对 add-only 的 admission rule：

```text
新增 guard line: reject as direct blame target
guard-protected old use: accept if parent code exists and root-cause-linked
nearby context only: accept only as low-confidence fallback
```

## 8. Fix-series exclusion

两个工具都在 OpenJPEG CVE-2020-27814 上把修复分支中的 patch commit 当成 BIC。必须加入 fix-series 排除。

候选若满足以下条件，应降权或拒绝：

1. 是 FIC merge commit 引入的 patch-series commit。
2. patch-id 与 FIC 或 FIC 子提交高度相似。
3. commit message 包含 `fix`、`fixes`、`security`、`CVE`，且时间紧邻 FIC。
4. candidate 与 FIC 之间没有任何 release tag。
5. diff 主要增加 guard 或修复逻辑，而不是引入 vulnerable behavior。

对应状态：

```text
REJECT_FIX_SERIES_COMMIT
LOW_CONFIDENCE_NEAR_FIX_PATCH
```

## 9. Branch-aware affected-version 转换接口

BIC Judge 只输出 BIC cluster，不直接输出 affected versions。

VulnVersion Agent 应执行：

```text
canonical BIC cluster
-> per-release-line equivalent BIC
-> per-release-line FIC/backport
-> affected interval
```

每条 release line 独立判断：

```text
tag contains line_specific_BIC
AND NOT tag contains line_specific_FIC
AND tag passes version_registry
```

不能只用全局 `BIC <= tag <= FIC` 时间区间。时间只能作为 fallback。

转换状态：

```text
CONVERTED
NO_BIC
BIC_NOT_IN_RELEASE_HISTORY
NO_LINE_EQUIVALENT_BIC
NO_LINE_FIC
FIX_SERIES_CANDIDATE
SHALLOW_HISTORY
NON_MONOTONIC_LINE
```

## 10. Graph 事件映射

建议在 `vulngraph_judge` 中新增或复用以下节点类型：

```text
RootCauseHypothesis
VulnerablePredicate
FixPredicate
PreFixAnchor
AnchorAdmission
BlameObservation
BICCandidate
BICBoundaryEvaluation
BICCluster
BranchEquivalentCommit
VersionConversionStatus
```

allowed_use 建议：

```text
root_cause_evidence:
  RootCauseHypothesis
  VulnerablePredicate
  FixPredicate
  PreFixAnchor

target_verdict_evidence:
  AnchorAdmission
  BlameObservation
  BICBoundaryEvaluation
  BICCluster
  VersionConversionStatus

navigation_only:
  RepoNavigationHint
  FunctionHistoryHint
  RenameHistoryHint

offline_eval_only:
  ground truth affected_version
  oracle-best-candidate
```

这保持一个边界：

```text
CVE/CWE/NVD 文本可以 orient root cause，
但最终 BIC 和 affected-version 只能由 Git/code evidence 支撑。
```

## 11. 最小可落地版本

第一版不需要直接上 Neo4j，也不需要完整重写 Stage3。

建议 P0 实现：

1. 新增 `TopKPreFixAnchor` JSON schema。
2. 从 FIC diff 和 root cause prompt 生成 top-k anchors。
3. 写一个 deterministic anchor validator：
   - 文件是否存在于 `C_fix^1`。
   - 行号/符号是否能定位。
   - 文件角色是否可接受。
4. 对 accepted anchors 做 `git blame`。
5. 对每个 blame commit 和 parent 构造 BICBoundaryJudge prompt。
6. 输出 BIC cluster。
7. 复用现有 `evaluate_bic_baselines.py` 做 BIC-to-version 评估。

P0 不解决所有 branch-equivalence，但必须保留状态：

```text
BIC_NOT_IN_RELEASE_HISTORY
NO_LINE_EQUIVALENT_BIC
```

否则 httpd 这种主干 BIC/维护分支 backport case 会被错误归因成 BIC Judge 失败。

## 12. 消融实验

在 30 CVE pilot 上先跑：

1. `deleted_blame_only`
2. `agentic_context_fallback`
3. `mas_semantic_anchor`
4. `topk_semantic_anchor_no_judge`
5. `topk_semantic_anchor_with_bic_judge`
6. `+ fix_series_exclusion`
7. `+ function_rename_history`
8. `+ branch_aware_converter`

每组报告：

```text
anchor coverage
accepted anchor count
candidate count
accepted BIC count
NO_BIC count
FIX_SERIES rejected count
BIC_NOT_IN_RELEASE_HISTORY count
Precision / Recall / Micro-F1
CVE exact accuracy
tokens / latency
```

分层报告：

```text
add-only
merge-FIC
multi-FIC
cross-branch/backport
rename/refactor
large-history repo
```

## 13. 论文中的核心表述

可以把方法贡献写成：

```text
We decompose vulnerability-affected version identification into
root-cause-grounded anchor generation, BIC boundary judgement, and
branch-aware version conversion. Unlike direct SZZ-style blame, our method
asks the root-cause agent to produce top-k pre-fix vulnerable anchors and
requires a judge agent to verify each candidate BIC by checking the vulnerable
state in the candidate commit and its absence in the parent commit.
```

中文表达：

```text
本文不将补丁修改行直接等同于漏洞引入证据，而是先由 Root Cause Agent
提取修复前承载漏洞语义的 top-k 代码锚点，再由 Judge Agent 对这些锚点
沿历史回溯得到的候选提交执行边界判定。只有当候选提交中漏洞语义成立，
且其父提交中漏洞语义不成立时，该提交才被接受为 BIC。随后，系统将
canonical BIC 映射到不同 release line 上的等价引入点，并结合分支上的
修复提交计算 affected versions。
```

## 14. 当前结论

对你的系统而言，最优融合不是：

```text
Agentic-SZZ + MAS-SZZ 简单 ensemble
```

而是：

```text
MAS-SZZ 的 root-cause-guided semantic anchors
+ Agentic-SZZ 的 structured evidence graph and bounded search
+ VulnVersion 的 branch-aware affected-version converter
```

Judge Agent 的关键职责也不是“帮 LLM 猜 BIC”，而是执行可审计的边界证明：

```text
anchor 是否真实存在于修复前代码？
candidate commit 是否真的包含该漏洞语义？
parent commit 是否不包含该漏洞语义？
candidate 是否只是修复系列提交？
candidate 是否能映射到 release history？
```

这套设计直接针对当前 pilot 中暴露的 gap：Agentic-SZZ anchor 语义不足、MAS-SZZ reviewer 过宽、add-only blame 错位、fix-series 误判，以及 BIC 到 affected versions 的分支映射问题。
