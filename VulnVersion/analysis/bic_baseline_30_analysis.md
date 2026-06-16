# Agentic-SZZ 与 MAS-SZZ：30 CVE 实验深度分析

## 1. 评估对象与口径

数据集：`DataSet/BaseDataSet_30.json`，30 个 CVE，9 个仓库。

输入结果：

- Agentic-SZZ：`results/eval/BaseDataSet30_full_20260611_085254.json`
- MAS-SZZ：`result/save_logs_B30/**/result.json`

两个工具只输出 BIC，不直接输出 affected versions。本报告使用统一转换器：

`scripts/evaluate_bic_baselines.py`

转换的基础条件是：

1. 从本地 Git 仓库取得全部 tag。
2. 使用 `version_registry.py` 的九仓库规则过滤 RC、beta、内部 tag 等无关版本。
3. tag 必须包含至少一个预测 BIC。
4. tag 不能包含任一 fixing commit。
5. 对时间有歧义，因此同时报告两种口径：
   - `topology_only`：只使用 Git 可达性。
   - `latest_fic_time`：在拓扑条件上，额外要求 release 时间不晚于最晚 FIC。

`latest_fic_time` 更接近字面上的“BIC-FIC 期间”，但会错误截断在主修复之后仍未回补的维护分支；`topology_only` 能保留这些维护分支，但会将没有合并该 FIC 的未来分支误判为受影响。最终正式实验不应只选其中一个，而应实现 branch-aware 转换。

## 2. 数据完整性检查

### Agentic-SZZ

- 输入记录：30。
- 生成 BIC：25。
- 空 BIC：5。
- BIC coverage：83.33%。
- 原始结果里的 `ground_truth` 全为空，因此 Agentic-SZZ 自带 CSV 中的 `F1=0` 不能作为本实验结论。它只是把“没有 BIC 标签”当成了“预测错误”。

空 BIC：

- CVE-2020-13904
- CVE-2020-19667
- CVE-2022-0171
- CVE-2020-15389
- CVE-2020-13164

### MAS-SZZ

- 输入记录：30。
- 结果文件：29。
- 29 个结果全部包含至少一个 BIC。
- 缺失结果：CVE-2020-11993，FIC `63a0a87efa0925514d15c211b508f6594669888c`。
- Result/BIC coverage：96.67%。
- 没有日志证明该条是模型失败、进程中断还是未调度，因此只能标记为 missing result。

### 仓库限制

本地 `VulnVersion/repo/linux` 是 shallow repository。其余八个仓库不是 shallow/partial clone。Linux 结果可以用于诊断，但正式论文数字必须在完整 Linux 历史上复算。

## 3. 最终指标

### 3.1 Topology-only

| 方法 | BIC coverage | Precision | Recall | Micro F1 | Macro F1 | Vulnerability-level accuracy | Exact CVE |
|---|---:|---:|---:|---:|---:|---:|---:|
| Agentic-SZZ | 83.33% | 56.59% | 30.00% | 39.21% | 65.36% | 43.33% | 13/30 |
| MAS-SZZ | 96.67% | 65.22% | 78.93% | 71.42% | 76.41% | 50.00% | 15/30 |

Topology-only 的主要问题是跨分支未来版本误报。例如 FIC 位于 OpenSSL 1.1.1 分支时，未包含该 FIC 的 OpenSSL 3.x tag 也可能被保留。

### 3.2 Latest-FIC time bound

| 方法 | BIC coverage | Precision | Recall | Micro F1 | Macro F1 | Vulnerability-level accuracy | Exact CVE |
|---|---:|---:|---:|---:|---:|---:|---:|
| Agentic-SZZ | 83.33% | 99.66% | 28.81% | 44.69% | 64.21% | 43.33% | 13/30 |
| MAS-SZZ | 96.67% | 93.66% | 78.33% | 85.31% | 76.82% | 46.67% | 14/30 |

时间截断几乎消除了 Agentic-SZZ 的 FP，但没有解决其严重 FN。MAS-SZZ 的 micro F1 从 71.42% 升至 85.31%，说明大部分拓扑-only FP 来自修复后分叉版本，而不是 BIC 本身完全错误。

但是 exact accuracy 从 50.00% 降至 46.67%，说明全局时间上界也删除了部分真实受影响维护版本。这个敏感性变化本身就是实验结论：版本转换器会显著改变最终排名。

### 3.3 MAS-SZZ 多 BIC 策略

在 `latest_fic_time` 下：

| 策略 | Micro F1 | Macro F1 | Vulnerability-level accuracy |
|---|---:|---:|---:|
| union | 85.31% | 76.82% | 46.67% |
| top1 | 84.60% | 76.10% | 43.33% |

差异主要来自 CVE-2020-8231。两个 BIC 分别对应 `lastconnect` 的两个语义位置，取并集才能恢复完整 affected versions。多 BIC 不能简单压缩成 top1；应保留“一个 root cause 对应多个历史引入点”的表达。

## 4. 按仓库结果：Latest-FIC time bound

### Agentic-SZZ

| Repo | Precision | Recall | F1 | Exact |
|---|---:|---:|---:|---:|
| FFmpeg | 100.0% | 3.4% | 6.7% | 2/3 |
| ImageMagick | 100.0% | 21.0% | 34.8% | 1/3 |
| curl | 100.0% | 63.9% | 78.0% | 2/3 |
| httpd | 100.0% | 55.0% | 71.0% | 1/3 |
| linux | 100.0% | 84.7% | 91.7% | 4/6 |
| openjpeg | 100.0% | 16.7% | 28.6% | 0/3 |
| openssl | 98.3% | 81.4% | 89.1% | 1/3 |
| qemu | 100.0% | 98.6% | 99.3% | 2/3 |
| wireshark | 100.0% | 14.8% | 25.9% | 0/3 |

Agentic-SZZ 的特征是截断后 precision 极高、recall 极低。它经常找到一个较晚的 BIC，因此只覆盖真实区间的后半段。

### MAS-SZZ

| Repo | Precision | Recall | F1 | Exact |
|---|---:|---:|---:|---:|
| FFmpeg | 100.0% | 59.0% | 74.2% | 2/3 |
| ImageMagick | 82.6% | 100.0% | 90.5% | 1/3 |
| curl | 100.0% | 100.0% | 100.0% | 3/3 |
| httpd | 100.0% | 47.5% | 64.4% | 1/3 |
| linux | 98.3% | 98.3% | 98.3% | 4/6 |
| openjpeg | 100.0% | 44.4% | 61.5% | 1/3 |
| openssl | 98.3% | 84.3% | 90.8% | 1/3 |
| qemu | 97.3% | 98.6% | 97.9% | 1/3 |
| wireshark | 94.0% | 74.3% | 83.0% | 0/3 |

MAS-SZZ 在 curl、Linux、Wireshark 上的 recall 优势明显，但仍不能正确恢复 Wireshark 三个 CVE 的完整精确集合。

## 5. Add-only 结果

30 个 CVE 中有 5 个 fixing commits 是 add-only：

- CVE-2020-12284
- CVE-2020-19667
- CVE-2022-0286
- CVE-2022-0433
- CVE-2020-11647

### Topology-only

| 方法 | Mean per-CVE F1 | Exact | BIC coverage |
|---|---:|---:|---:|
| Agentic-SZZ | 64.8% | 3/5 | 4/5 |
| MAS-SZZ | 94.3% | 4/5 | 5/5 |

### Latest-FIC time bound

| 方法 | Mean per-CVE F1 | Exact | BIC coverage |
|---|---:|---:|---:|
| Agentic-SZZ | 46.5% | 2/5 | 4/5 |
| MAS-SZZ | 78.5% | 3/5 | 5/5 |

结论不是“add-only 无法用 blame”，而是“不能 blame 新增的 guard 本身”。MAS-SZZ 先解释 guard 在保护什么，再定位 parent 中已存在的危险读取、危险解引用、缺失 callback 或递归入口，然后 blame 这些 pre-fix statements。这比固定 ±2 context 更有效。

## 6. 两个工具真正值得学习的机制

### 6.1 Agentic-SZZ

值得保留：

1. 将直接 blame、blame ancestor、BFC ancestor 放入同一候选空间。
2. 用 File/Function 节点记录候选之间的历史关联。
3. Agent 只获得有限图查询工具，轨迹可审计。
4. 保存 token、成本、步骤和阶段耗时。

不应直接照搬：

1. Add-only fallback 只是 blame 新增行附近 ±2 行，缺少“新增 guard -> 被保护语句”的语义映射。
2. 新文件直接跳过，导致 add-only new-file 没有候选。
3. fallback context 被计入 `total_deleted_lines`，随后被错误标记为普通 blameable case。
4. TKG 主要按修改文件扩展历史，语义范围过宽；单个 httpd 案例消耗 1,714,355 input tokens、61 agent steps。
5. TKG 模式捕获 Agent 异常后返回空 BIC；agent-only 模式却会 fallback 到 top candidate，行为不一致。
6. 置信度主要来自候选形态或 Agent 自报，未与最终版本区间风险校准。

### 6.2 MAS-SZZ

值得保留：

1. `patch + CVE description + commit message -> structured root cause`。
2. Root Cause Reviewer 对初始解释进行反馈重试。
3. 将 hunks 按修改意图分组，并过滤与 root cause 无关的组。
4. 语义不完整时补充函数、类型和调用上下文。
5. 从 root cause 反向定位 pre-fix vulnerable statements。
6. 对每个 statement 分别回溯，允许一个 CVE 返回多个 BIC。
7. 正常回溯失败后，仍有 deleted/context-line vote 兜底。

实验支持这一设计：

- 2 个 vulnerable statements 的 8 个案例，平均 per-CVE F1 为 95.3%。
- 1 个 statement 的 16 个案例，平均 F1 为 74.6%。
- 0 个 statement 的 3 个案例，平均 F1 为 56.4%。

样本很小，不能推断因果，但说明“多个互补语义锚点”值得成为 Root Cause Agent 的显式输出。

需要修正：

1. 29/29 root cause 全部通过 reviewer，gate 没有区分度。Reviewer 更像格式/一致性确认，而不是错误检测器。
2. 当回溯第一步判断 `exists=False` 时，源码仍把该 blame commit 当 BIC 返回。这与“C_j 有 bug、parent 无 bug”的边界定义冲突，应当 abstain 或扩大搜索。
3. `MAX_TRACE_DEPTH=20` 会将“达到深度上限”误包装成找到 BIC，必须输出 censored/unknown 状态。
4. fallback 用 root-cause 字符串关键词给删除行打分，容易选中生成文件、错误码表、文档和测试。例如 CVE-2021-23840 的三个 anchor 全来自 `crypto/err/openssl.txt`，最终 BIC 只是“message strings”提交。
5. 同一模型同时生成和审查 root cause，失败相关性很高。
6. 结果未保存逐案例总耗时，无法与 Agentic-SZZ 做严格 latency 对比。

## 7. 典型失败案例

### 7.1 OpenJPEG CVE-2020-27814：把 fix-series commit 当 BIC

两个方法都输出：

`649298dcf84b2f20cfe458d887c1591db47372a6`

该提交信息为 `Encoder: grow again buffer size ... (fixes #1283)`，位于 merge FIC 之前，是修复分支中的实际 patch，而不是漏洞引入提交。它和 FIC 之间没有 release tag，因此两个方法最终预测空 affected versions。

应增加 `fix-series exclusion`：

- 如果 FIC 是 merge commit，排除 merge 引入的 patch-series commits。
- 排除补丁组中与 FIC patch-id 等价的提交。
- 对包含 `fix/fixes/CVE/security` 且紧邻 FIC 的候选降低优先级。

### 7.2 httpd CVE-2020-11984：跨分支等价 BIC

MAS-SZZ 找到 trunk 中最初引入 UWSGI 模块的提交 `da54e90...`，语义上合理，但该提交不是 2.4 release branch 的祖先，因此转换为 0 个 affected versions。

Agentic-SZZ 找到 2.4 分支的 backport `99c59e09...`，恰好恢复全部 14 个版本。

这说明一个“正确的语义 BIC”不一定能直接用于版本转换。VulnVersion 需要建立：

`canonical BIC -> cherry-pick/backport/equivalent introduction commits -> release lines`

### 7.3 Wireshark CVE-2020-15466：BIC 太晚导致严重 FN

MAS-SZZ 选择 2019 年提交 `1e630b42...`，latest-FIC 口径只恢复 12/244 个 GT 版本。Agentic-SZZ 选择 2017 年提交，恢复 76/244。

MAS 的 root cause 是正确的，但 vulnerable statement 只锚定了当前 `if(tree)` 位置，没有继续追踪该控制结构更早的引入历史。Root Cause Agent 正确不代表 BIC 边界正确。

### 7.4 OpenSSL CVE-2021-23840：fallback anchor 污染

MAS-SZZ 没有得到 vulnerable statements，fallback 从错误字符串表选择三个 anchor，得到与真实整数溢出逻辑无关的 BIC。

fallback 必须增加文件角色过滤：

- 优先源代码与声明文件。
- 降权 generated/error registry/changelog/test fixture。
- anchor 必须与 root-cause symbol、数据依赖或控制依赖建立结构化关系，不能只做字符串包含。

## 8. Root Cause Agent 设计建议

### 8.1 输出结构

不要只输出一段 root-cause text。建议强制输出：

```json
{
  "failure_mode": "",
  "trigger": "",
  "violated_invariant": "",
  "vulnerable_state": "",
  "propagation": [],
  "sink": "",
  "fix_mechanism": "",
  "pre_fix_anchors": [
    {
      "file": "",
      "symbol": "",
      "line": 0,
      "role": "source|propagation|sink|missing_guard_target|state_declaration",
      "evidence": "",
      "confidence": 0.0
    }
  ],
  "excluded_hunks": [],
  "uncertainties": []
}
```

### 8.2 Reviewer gate

Reviewer 至少检查：

1. Patch necessity：该修复是否真的针对所述 failure mode。
2. Parent existence：pre-fix anchor 是否实际存在于 FIC parent。
3. Counterfactual：移除新增 guard/validation 后，触发链是否闭合。
4. Evidence closure：trigger -> vulnerable state -> sink 是否都有代码证据。
5. Alternative explanation：是否只是重构、API 迁移或测试修改。
6. Anchor usability：anchor 是否能被 blame、是否位于生成文件、是否跨 rename。

Reviewer 应允许 `REJECT` 和 `INSUFFICIENT_EVIDENCE`，不能强制每条都通过。

### 8.3 Add-only 专用路径

1. 识别新增语句类型：guard、bounds check、initialization、callback registration、cleanup、lock、depth limit。
2. 从新增语句提取被保护对象和条件变量。
3. 在 parent 中定位：危险使用点、状态声明、数据源、调用者、递归边。
4. 生成多个带角色的 pre-fix anchors。
5. 只对这些 anchors blame；±N context 仅作为最后兜底。

## 9. BIC Search Agent 设计建议

候选源应分层并记录来源：

1. `direct_deleted_blame`
2. `semantic_anchor_blame`
3. `symbol_history`
4. `rename_history`
5. `callgraph_predecessor`
6. `patch_series_ancestor`
7. `branch_equivalent_introduction`

对每个候选执行真正的边界判定：

1. 在候选 `C_j` 读取 root-cause 相关 symbol/function，而不是只读 commit diff。
2. 在其 parent `C_j^1` 读取同一语义对象。
3. 只有 `bug(C_j)=true` 且 `bug(C_j^1)=false` 才接受。
4. 若第一步就是 no-bug，不得把该提交返回为 BIC。
5. 路径/函数 rename 时，必须更新 anchor path 和 line mapping。
6. 达到深度或 token 上限时输出 `CENSORED`，不能伪装成成功。

## 10. VulnVersion Agent 设计建议

版本转换应是独立、确定性、可审计模块，不应让 LLM 直接生成版本列表。

建议数据结构：

```text
Canonical Root Cause
  -> BIC cluster
       -> equivalent introductions by release line
  -> FIC cluster
       -> backports by release line
  -> ReleaseLine graph
       -> affected interval per line
```

每条 release line 独立计算：

```text
contains(line_specific_BIC)
AND NOT contains(line_specific_FIC)
AND release_tag_passes_registry
```

时间只用于没有拓扑证据时的 fallback，不应作为全局硬删除规则。

必须输出以下诊断状态：

- `NO_BIC`
- `BIC_NOT_IN_RELEASE_HISTORY`
- `FIX_SERIES_CANDIDATE`
- `NO_LINE_EQUIVALENT_BIC`
- `NO_LINE_FIC`
- `SHALLOW_HISTORY`
- `NON_MONOTONIC_LINE`
- `CONVERTED`

## 11. 下一轮实验设计

### 11.1 固定统一转换器

所有 BIC baseline 必须共用同一转换器，至少报告：

1. topology-only。
2. global time-bound sensitivity。
3. branch-aware 主结果。

### 11.2 分层评估

不要只看最终 F1：

| 层 | 指标 |
|---|---|
| Root cause | reviewer reject rate、evidence closure、人工正确率 |
| Anchor | statement localization precision、可 blame 比例、add-only coverage |
| Candidate retrieval | candidate recall@K、GT-compatible interval recall@K |
| Candidate selection | top1、MRR、abstention accuracy |
| Version conversion | exact set、micro/macro F1、line coverage、unmapped tags |
| Cost | calls、tokens、latency、Git queries、graph build time |

由于数据集没有 BIC ground truth，可增加两个只用于分析的 oracle：

1. `oracle-best-candidate`：从工具产生的候选中选择 downstream F1 最高者，测候选召回上限。
2. `oracle-line-equivalence`：允许为每条 release line 选择一个等价 BIC，测 branch-aware 转换上限。

这两个 oracle 不能作为正式方法分数，但能区分问题在候选生成、候选选择还是版本转换。

### 11.3 Ablation 矩阵

建议至少运行：

1. Deleted-line blame。
2. Agentic ±2 context fallback。
3. MAS semantic vulnerable statements。
4. Semantic statements + fix-series exclusion。
5. Semantic statements + function/rename history。
6. 完整方案 + branch-equivalent BIC/FIC clusters。

每组同时按 add-only、merge-FIC、多 FIC、跨分支、rename/refactor 分层。

## 12. 当前结论

1. 在这 30 个 CVE 上，MAS-SZZ 的 downstream affected-version 表现整体优于 Agentic-SZZ，核心优势来自 root-cause-guided vulnerable statement 定位和多 BIC 保留。
2. Agentic-SZZ 最值得学习的是结构化历史候选图和受限工具搜索，而不是其 add-only fallback 或空结果处理。
3. MAS-SZZ 最值得迁移的是 `root cause -> semantic anchor -> iterative blame boundary`，但 reviewer、fallback anchor 和边界判定源码需要修正。
4. Add-only 不应转化为“blame 新增行附近代码”，而应转化为“解释新增修复保护的旧语义对象，再 blame 旧对象”。
5. 最终分数对 BIC-to-version adapter 极其敏感。Topology-only 与时间截断使 MAS micro F1 从 71.42% 变化到 85.31%。正式论文必须把 branch-aware adapter 固定为公共实验组件。
6. 30 个样本只适合机制验证和消融设计，不能据此宣称统计显著或 SOTA。
