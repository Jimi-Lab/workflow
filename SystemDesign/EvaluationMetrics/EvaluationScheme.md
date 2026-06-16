# 四篇论文评估指标提取与复现公式

## 0. 说明

- 本文件只基于以下四篇 PDF 正文提取：
  - `Replication\BaseLine(Vulnerability-affected versions identification How far are we)\Direct_Comparison_Papers(Baseline_Paper+Code)\Vulnerability-affected versions identification：How far are we.pdf`
  - `Replication\BaseLine(Vulnerability-affected versions identification How far are we)\RelatedWork_VulnVersionValidation\AgentSZZ：Teaching the LLM Agent to Play Detective with Bug-Inducing Commits.pdf`
  - `Replication\BaseLine(Vulnerability-affected versions identification How far are we)\RelatedWork_VulnVersionValidation\CaVulner：Automated Context-Aware Identification of Vulnerable Versions.pdf`
  - `Replication\BaseLine(Vulnerability-affected versions identification How far are we)\RelatedWork_VulnVersionValidation\TDSC-Automatically Identifying CVE Affected Versions With Patches and Developer Logs.pdf`
- 目标不是复述实验结果，而是提炼“论文实际使用了哪些评估标准，以及这些标准如何计算”。
- 对每个指标，我都标注了两类状态：
  - `论文显式给出`：正文明确写出了定义或公式。
  - `为便于复现补全`：论文使用了该指标，但正文没有把公式完整打印出来；这里给出标准计算式，方便后续直接实现。
- 特别注意：
  - 这四篇论文都**没有**把 `CVE-level F1` 当作主指标。
  - 对“受影响版本识别”任务，主流做法是：
    - `CVE-level Accuracy`
    - `CVE-level No-Miss Ratio / No-Miss`
    - `Version-level Precision / Recall / F1`
  - 对 LLM/Agent 论文，额外常见的是：
    - `token 消耗`
    - `API cost`
    - `运行时间`
    - `turn 数`
    - `subset recall`
    - `相对提升`

## 1. 统一符号

为避免四篇论文记号不统一，下面先给出统一记号。

- 对受影响版本识别任务：
  - 设第 `i` 个 CVE 的真实受影响版本集合为 `GT_i`
  - 设第 `i` 个 CVE `的预测受影响版本集合为`Pred_i`
  - 数据集中的 CVE 总数为 `N`
- 对 BIC 识别任务：
  - 设第 `i` 个修复提交对应的真实 bug-inducing commit 集合为 `GT(c_i)`
  - 设预测集合为 `Pred(c_i)`
- 对版本级统计：
  - `TP_v = Σ_i |GT_i ∩ Pred_i|`
  - `FP_v = Σ_i |Pred_i \ GT_i|`
  - `FN_v = Σ_i |GT_i \ Pred_i|`
- 对子集评估：
  - 若只在某个子集 `S` 上计算，则把上面的求和范围限制到 `i ∈ S`
- 对资源指标：
  - `InputTokens_i`、`OutputTokens_i`、`Time_i`、`Cost_i` 表示第 `i` 个样本的输入 token、输出 token、运行时间和 API 成本

## 2. Vulnerability-affected versions identification: How far are we?

### 2.1 论文实际使用的评估维度

该文的主评估在正文第 4-5 页，核心有两层粒度：

- `Vulnerability-level Evaluation`
- `Version-level Evaluation`

此外还使用了以下补充评估维度：

- 标注一致性：`Cohen's Kappa`
- 标注人工成本：`平均每个 CVE 的人工耗时`
- Patch sensitivity 分层评估：
  - `Add-only / Del-only / Mixed`
  - `Single-function / Multi-function single-file / Multi-function multi-file`
  - `Single-branch / Multi-branch`
- Tool combination 评估：
  - `Vulnerability-level Accuracy`
  - `Version-level F1`
  - 相对提升百分比
- Root cause analysis：
  - 100 个样本上的错误数量/比例

### 2.2 主效果指标与公式

#### 2.2.1 CVE-level Accuracy

- 论文状态：`论文显式给出`
- 论文定义：只有当某个 CVE 的预测版本集合与真值集合完全一致时，才记为正确。
- 公式：

```text
True_exact = Σ_i 1[Pred_i = GT_i]
Accuracy_CVE = True_exact / N
```

- 说明：
  - 这是严格的 exact-set match 指标。
  - 任何一个额外版本或漏掉版本，都会让该 CVE 记为错误。

#### 2.2.2 No-Miss Ratio (NMR)

- 论文状态：`论文显式给出`
- 论文定义：若预测集合包含了该 CVE 的全部真值版本，即使多报了一些额外版本，也记为 `No-Miss`。
- 公式：

```text
NoMiss = Σ_i 1[GT_i ⊆ Pred_i]
NMR = NoMiss / N
```

- 说明：
  - 这是一个“更偏召回导向”的 CVE 级指标。
  - 它允许过报，不允许漏报。
  - 对漏洞管理场景很重要，因为漏掉受影响版本通常比多报更危险。

#### 2.2.3 Version-level Precision

- 论文状态：`论文使用，但正文未打印公式；这里为标准补全`
- 公式：

```text
Precision_version = TP_v / (TP_v + FP_v)
```

- 其中：

```text
TP_v = Σ_i |GT_i ∩ Pred_i|
FP_v = Σ_i |Pred_i \ GT_i|
```

#### 2.2.4 Version-level Recall

- 论文状态：`论文使用，但正文未打印公式；这里为标准补全`
- 公式：

```text
Recall_version = TP_v / (TP_v + FN_v)
```

- 其中：

```text
FN_v = Σ_i |GT_i \ Pred_i|
```

#### 2.2.5 Version-level F1

- 论文状态：`论文使用，但正文未打印公式；这里为标准补全`
- 公式：

```text
F1_version = 2 * Precision_version * Recall_version / (Precision_version + Recall_version)
```

#### 2.2.6 CVE-level No-Miss 与 Version-level Recall 的区别

- 论文状态：`正文显式讨论`
- 复现时要明确区分：
  - `NMR` 是以“整个 CVE 的版本集合是否完整覆盖”为单位。
  - `Version-level Recall` 是把所有版本展平之后逐版本统计。
- 同一个系统，完全可能出现：
  - `NMR` 较低
  - `Version-level F1` 较高
- 原因是 version-level 指标允许“部分命中”，而 CVE-level Accuracy / NMR 对整集合更严格。

### 2.3 标注质量与人工成本指标

#### 2.3.1 Cohen's Kappa

- 论文状态：`论文显式报告数值，未打印公式`
- 文中数值：`0.83`
- 复现公式：

```text
κ = (p_o - p_e) / (1 - p_e)
```

- 其中：
  - `p_o`：观察到的一致率
  - `p_e`：随机一致率

#### 2.3.2 平均标注时间

- 论文状态：`论文显式给出`
- 文中描述：平均每个 CVE 约 `0.5 person-hours`
- 复现公式：

```text
AvgAnnotationHoursPerCVE = TotalPersonHours / NumberOfCVEs
```

### 2.4 分层与鲁棒性评估

这篇论文没有引入新的“数学指标”，而是把主指标按不同维度切片。

#### 2.4.1 Patch type sensitivity

- 论文状态：`正文显式使用`
- 子集：
  - `Add-only`
  - `Del-only`
  - `Mixed`
- 对每个子集，仍然计算：
  - `Accuracy_CVE`
  - `NMR`
  - `Precision_version`
  - `Recall_version`
  - `F1_version`
- 子集公式：

```text
Metric_on_subset(S) = 在 i ∈ S 上按原公式重新计算
```

#### 2.4.2 Modification scope sensitivity

- 论文状态：`正文显式使用`
- 子集：
  - `Single-function`
  - `Multi-function single-file`
  - `Multi-function multi-file`
- 仍然使用同一套主指标。

#### 2.4.3 Branch setting sensitivity

- 论文状态：`正文显式使用`
- 子集：
  - `Single-branch`
  - `Multi-branch`
- 仍然使用同一套主指标。

### 2.5 组合策略评估

#### 2.5.1 Inclusion Strategy

- 论文状态：`正文显式描述策略，未打印集合公式；这里为复现补全`
- 含义：多个工具的预测结果取并集。
- 公式：

```text
Pred_i^(incl, T) = ⋃_(t ∈ T) Pred_i^(t)
```

- 然后再对 `Pred_i^(incl, T)` 计算：
  - `Accuracy_CVE`
  - `F1_version`

#### 2.5.2 Voting Strategy

- 论文状态：`正文显式描述策略，未打印集合公式；这里为复现补全`
- 含义：若超过半数工具认为某个版本受影响，则把该版本判为受影响。
- 公式：

```text
Pred_i^(vote, T) = { v | Σ_(t ∈ T) 1[v ∈ Pred_i^(t)] > |T| / 2 }
```

#### 2.5.3 Best-in-Dimension Strategy

- 论文状态：`正文显式描述`
- 含义：先在几个维度上选表现最好的工具，再聚合其输出。
- 论文没有写死聚合公式，但从文字看是“aggregate their outputs”。
- 若后续复现，建议明确采用：

```text
Pred_i^(best-dim) = ⋃_(d ∈ Dimensions) Pred_i^(best_tool_for_d)
```

- 如果你采用别的聚合规则，必须在实验文档中单独声明。

#### 2.5.4 Relative Improvement

- 论文状态：`正文显式使用提升百分比，未打印公式`
- 复现公式：

```text
RelativeImprovement(metric) = (metric_new - metric_base) / metric_base
```

### 2.6 根因分析与采样统计指标

- 论文状态：`正文显式使用`
- 形式是“100 个随机样本里的错误占比/计数”，不是主效果指标。
- 可复现公式：

```text
ErrorShare(type) = Count(type) / SampleSize
```

- 例如：
  - 某阶段错误 49 例，则该错误占比 `49 / 100 = 49%`
  - 噪声 patch 占比 `Count(noisy_patches) / Count(sampled_patches)`

### 2.7 对 VulnVersion 的直接启发

- 如果你要对齐这篇论文，最重要的是同时报告：
  - `CVE-level Accuracy`
  - `CVE-level NMR`
  - `Version-level Precision`
  - `Version-level Recall`
  - `Version-level F1`
- 只报 version-level F1 会掩盖“整条版本区间没圈准”的问题。

## 3. AgentSZZ: Teaching the LLM Agent to Play Detective with Bug-Inducing Commits

### 3.1 论文实际使用的评估维度

这篇论文的任务不是受影响版本识别，而是 `bug-inducing commit (BIC) identification`。核心评估分四块：

- 效果指标：
  - `Precision`
  - `Recall`
  - `F1`
- 效率指标：
  - `Runtime`
  - `Token consumption`
  - `Interaction turns`
  - `Monetary cost`
  - `Per-turn information density`
- 消融评估：
  - 去掉 tools / domain knowledge / compression 后的 `Precision/Recall/F1`
  - 去掉 compression 后的 `tokens/cost` 变化
- 挑战场景评估：
  - `Cross-file Recall`
  - `Ghost Recall`
  - `Relative Improvement`
- 统计显著性：
  - `p < 0.001`

### 3.2 主效果指标与公式

#### 3.2.1 Precision

- 论文状态：`论文显式给出公式`
- 公式：

```text
Precision =
Σ_i |GT(c_i) ∩ Pred(c_i)| / Σ_i |Pred(c_i)|
```

#### 3.2.2 Recall

- 论文状态：`论文显式给出公式`
- 公式：

```text
Recall =
Σ_i |GT(c_i) ∩ Pred(c_i)| / Σ_i |GT(c_i)|
```

#### 3.2.3 F1

- 论文状态：`论文显式给出公式`
- 公式：

```text
F1 = 2 * Precision * Recall / (Precision + Recall)
```

### 3.3 重复运行与平均值

- 论文状态：`正文显式说明 AgentSZZ、LLM4SZZ、LLM4SZZ(5-mini) 运行 3 次并报告平均值`
- 复现公式：

```text
AvgMetric = (1 / R) * Σ_r Metric_r
```

- 其中 `R = 3`

### 3.4 效率与成本指标

#### 3.4.1 Runtime

- 论文状态：`论文显式使用`
- 含义：每种方法的平均运行时间，单位秒。
- 论文没有打印完整聚合公式，只说“averaged over three datasets”。
- 建议复现公式：

```text
AvgRuntime = (1 / M) * Σ_j Runtime_j
```

- `M` 可以是：
  - 数据集数
  - 或样本数
- 实验时必须单独声明你的聚合粒度。

#### 3.4.2 Token consumption

- 论文状态：`论文显式使用`
- 论文表格直接给 `Tokens`
- 若后续细化实现，建议拆成：

```text
AvgTokens = (1 / M) * Σ_j TotalTokens_j
```

#### 3.4.3 Interaction turns

- 论文状态：`论文显式使用`
- 公式：

```text
AvgTurns = (1 / M) * Σ_j Turns_j
```

#### 3.4.4 Monetary cost

- 论文状态：`论文显式使用 cost，但未打印计费公式`
- 论文表格直接报告美元成本。
- 便于你后续复现实验，建议使用：

```text
Cost_i =
(InputTokens_i / 10^6) * PriceInputPer1M
+ (OutputTokens_i / 10^6) * PriceOutputPer1M

AvgCost = (1 / M) * Σ_i Cost_i
```

- 注意：这里的 `PriceInputPer1M` 与 `PriceOutputPer1M` 取决于你实际使用的 API 服务商。

#### 3.4.5 Per-turn information density

- 论文状态：`论文显式使用概念，未打印公式`
- 文中例子：`34,657 / 5.7 ≈ 6,080 tokens/turn`
- 复现公式：

```text
InformationDensity = TotalTokens / Turns
```

- 如果要做总体统计：

```text
AvgInformationDensity = (1 / M) * Σ_i (TotalTokens_i / Turns_i)
```

### 3.5 挑战场景指标

#### 3.5.1 Cross-file Recall

- 论文状态：`论文显式使用`
- 计算对象：只在 `cross-file` 子集上计算 recall
- 复现公式：

```text
Recall_cross_file =
Σ_(i ∈ CrossFile) |GT(c_i) ∩ Pred(c_i)| / Σ_(i ∈ CrossFile) |GT(c_i)|
```

#### 3.5.2 Ghost Recall

- 论文状态：`论文显式使用`
- 复现公式：

```text
Recall_ghost =
Σ_(i ∈ Ghost) |GT(c_i) ∩ Pred(c_i)| / Σ_(i ∈ Ghost) |GT(c_i)|
```

#### 3.5.3 Cross-file / Ghost 占比

- 论文状态：`论文显式使用`
- 复现公式：

```text
CrossFileRatio = NumberOfCrossFileCases / NumberOfAllCases
GhostRatio = NumberOfGhostCases / NumberOfAllCases
```

#### 3.5.4 Relative Improvement

- 论文状态：`论文显式使用`
- 复现公式：

```text
RelativeImprovement(metric) = (metric_agent - metric_baseline) / metric_baseline
```

- 例如 cross-file recall 提升 `+300%`，就是按这个公式算。

### 3.6 消融与压缩收益指标

#### 3.6.1 消融后的 Precision / Recall / F1

- 论文状态：`论文显式使用`
- 仍使用 3.2 中同样的公式。

#### 3.6.2 Token reduction / Cost reduction

- 论文状态：`正文显式给出百分比，未打印公式`
- 复现公式：

```text
Reduction(metric) = (metric_before - metric_after) / metric_before
```

- 例如：
  - compression 带来的 token 降低
  - compression 带来的 cost 降低

### 3.7 工具行为分布指标

#### 3.7.1 Normalized tool usage proportion per turn

- 论文状态：`正文显式使用图，但未打印公式`
- 图 4 说明：每个 turn 上，不同工具调用量做归一化比例。
- 复现公式：

```text
ToolUsageShare(tool=t, turn=k) =
Calls(t, k) / Σ_u Calls(u, k)
```

### 3.8 统计显著性

#### 3.8.1 p-value

- 论文状态：`正文显式报告 p < 0.001`
- 未发现直接证据说明：
  - 使用了哪一种统计检验
  - 效应量如何计算
- 因此本文件只能记录：

```text
p < 0.001
```

- 如果你要复现实验，必须在自己的方法部分明确：
  - 检验类型
  - 零假设
  - effect size 公式

### 3.9 对 VulnVersion 的直接启发

- 如果你借鉴 AgentSZZ 这一类 agent 系统，建议至少补齐：
  - `Version-level Precision / Recall / F1`
  - `Runtime per case`
  - `Input / Output / Total tokens`
  - `Cost per case`
  - `Turns per case`
  - `Tokens per turn`
  - `Subset recall`（例如难例子集）

## 4. CaVulner: Automated Context-Aware Identification of Vulnerable Versions

### 4.1 论文实际使用的评估维度

这篇论文的评估维度非常完整，覆盖：

- `CVE-level Accuracy`
- `Version-level Precision / Recall / F1`
- 标注一致性：`Krippendorff's alpha`
- 消融评估：
  - `CVE-level Accuracy`
  - `Version-level Precision / Recall / F1`
- 不同 LLM 的效果评估：
  - 同样四个主指标
- 资源消耗评估：
  - `input tokens`
  - `output tokens`
  - `total tokens`
  - `cost`
  - `time`
  - 且是 `per CVE` 平均值

### 4.2 主效果指标与公式

#### 4.2.1 CVE-level Accuracy

- 论文状态：`论文显式给出公式`
- 定义：对某个 CVE，只有预测出的受影响版本集合与 GT 完全一致，才记为 `True`。
- 公式：

```text
Accuracy_CVE = |True| / (|True| + |False|)
```

#### 4.2.2 Version-level Precision

- 论文状态：`论文显式给出公式`
- 版本级定义：
  - 预测版本在 GT 中：`TP`
  - 预测版本不在 GT 中：`FP`
  - GT 中存在但没预测到：`FN`
- 公式：

```text
Precision_version = |TP| / (|TP| + |FP|)
```

#### 4.2.3 Version-level Recall

- 论文状态：`论文显式给出公式`
- 公式：

```text
Recall_version = |TP| / (|TP| + |FN|)
```

#### 4.2.4 Version-level F1

- 论文状态：`论文显式给出公式`
- 公式：

```text
F1_version = 2 * Precision_version * Recall_version / (Precision_version + Recall_version)
```

### 4.3 标注质量指标

#### 4.3.1 Krippendorff's alpha

- 论文状态：`论文显式报告数值，未打印公式`
- 文中数值：`0.78`
- 标准复现公式：

```text
Alpha = 1 - D_o / D_e
```

- 其中：
  - `D_o`：观察分歧
  - `D_e`：期望分歧

### 4.4 资源消耗指标

这篇论文对资源消耗的描述最接近你后续要做的 LLM 方法评估。

#### 4.4.1 Average input tokens per CVE

- 论文状态：`论文显式使用`
- 公式：

```text
AvgInputTokensPerCVE = TotalInputTokens / NumberOfCVEs
```

#### 4.4.2 Average output tokens per CVE

- 论文状态：`论文显式使用`
- 公式：

```text
AvgOutputTokensPerCVE = TotalOutputTokens / NumberOfCVEs
```

#### 4.4.3 Average total tokens per CVE

- 论文状态：`论文显式使用 total(k)`
- 公式：

```text
AvgTotalTokensPerCVE = AvgInputTokensPerCVE + AvgOutputTokensPerCVE
```

- 或按总量写成：

```text
AvgTotalTokensPerCVE = TotalTokens / NumberOfCVEs
```

#### 4.4.4 Average cost per CVE

- 论文状态：`论文显式使用 cost($)，未打印计费公式`
- 复现公式建议：

```text
Cost_i =
(InputTokens_i / 10^6) * PriceInputPer1M
+ (OutputTokens_i / 10^6) * PriceOutputPer1M

AvgCostPerCVE = Σ_i Cost_i / NumberOfCVEs
```

#### 4.4.5 Average time per CVE

- 论文状态：`论文显式使用`
- 公式：

```text
AvgTimePerCVE = TotalTime / NumberOfCVEs
```

### 4.5 消融评估指标

- 论文状态：`正文显式使用`
- 对 `CaVulner_diff`、`CaVulner_ast`、`CaVulner` 三个版本，比较：
  - `Accuracy_CVE`
  - `Precision_version`
  - `Recall_version`
  - `F1_version`
- 公式不变，仍使用 4.2 中公式。

### 4.6 LLM backbone 对比指标

- 论文状态：`正文显式使用`
- 对不同 LLM（如 `deepseek-v3`、`deepseek-r1`、`gpt-4.1-mini`、`qwen-turbo`），仍然比较：
  - `Accuracy_CVE`
  - `Precision_version`
  - `Recall_version`
  - `F1_version`
  - `AvgInputTokensPerCVE`
  - `AvgOutputTokensPerCVE`
  - `AvgTotalTokensPerCVE`
  - `AvgCostPerCVE`
  - `AvgTimePerCVE`

### 4.7 错误原因分解指标

- 论文状态：`正文显式给出失败数`
- 47 个失败 CVE 中，进一步分解：
  - 8 个错误包含过早版本
  - 39 个未覆盖完整 vulnerable range
  - 27 个语义等价判断失误
  - 14 个 duplicated commit 识别错误
  - 6 个初始 code localization 错误
- 复现时可用的比例公式：

```text
FailureCauseShare(cause) = Count(cause) / NumberOfFailedCVEs
```

### 4.8 对 VulnVersion 的直接启发

- 如果你要对齐 CaVulner 这种 LLM 版本识别方法，至少应当同时输出：
  - `CVE-level Accuracy`
  - `Version-level Precision`
  - `Version-level Recall`
  - `Version-level F1`
  - `AvgInputTokensPerCVE`
  - `AvgOutputTokensPerCVE`
  - `AvgTotalTokensPerCVE`
  - `AvgCostPerCVE`
  - `AvgTimePerCVE`

## 5. TDSC: Automatically Identifying CVE Affected Versions With Patches and Developer Logs

### 5.1 论文实际使用的评估维度

这篇论文比前三篇更早，评估口径和现代受影响版本识别论文不完全一致，但它用到的指标很多：

- 效果指标：
  - `Precision`
  - `Recall`
  - `Lower-bound Recall`
  - `Correct rate`
- 分任务评估：
  - `R1`：确定最后 vulnerable version
  - `R2`：确定每个 branch 的最后 vulnerable version
  - `R3`：确定第一个 vulnerable version
- 数据质量评估：
  - `NVD false positive rate`
  - `NVD false negative rate`
  - `changelog missing-record rate`
- 工作量评估：
  - `manual inspection counts`
  - `man-hours spent`
- 与 ReDeBug / VUDDY 的对比：
  - `Precision`
  - `Recall`

### 5.2 主效果指标与公式

#### 5.2.1 Precision

- 论文状态：`论文显式给出公式`
- 公式：

```text
Precision = TP / (TP + FP)
```

#### 5.2.2 Recall

- 论文状态：`论文显式给出公式`
- 公式：

```text
Recall = TP / (TP + FN)
```

### 5.3 R1 / R2 的 lower-bound recall

#### 5.3.1 R1: Last vulnerable version

- 论文状态：`正文显式报告 100% precision 和 96% lower-bound recall，但未打印 recall 计算式`
- 从正文描述可复现为：

```text
LowerBoundRecall_R1 = 1 - MissedCases_sample / SampledCVEs
```

- 文中样例：

```text
SampledCVEs = 100
MissedCases_sample = 4
LowerBoundRecall_R1 = 96%
```

#### 5.3.2 R2: Last vulnerable version in each branch

- 论文状态：`正文显式报告 100% precision 和 98% recall`
- 可复现公式同样是：

```text
LowerBoundRecall_R2 = 1 - MissedCases_sample / SampledCVEs
```

- 文中样例：

```text
SampledCVEs = 100
MissedCases_sample = 2
LowerBoundRecall_R2 = 98%
```

### 5.4 R3 的 lower-bound recall 与 correct rate

#### 5.4.1 R3 lower-bound recall

- 论文状态：`正文显式给出数字和保守假设，未直接打印公式`
- 论文逻辑：
  - 把无法确认的 74 个版本全部按最坏情况当作 FN
  - 再加上已确认的 39 个 FN
  - 得到总 FN = 113
  - TP = 4669
- 复现公式：

```text
LowerBoundRecall_R3 = TP / (TP + FN_worst_case)
```

- 文中样例：

```text
TP = 4669
FN_worst_case = 113
LowerBoundRecall_R3 = 4669 / (4669 + 113) = 97.6%
```

#### 5.4.2 Correct rate

- 论文状态：`正文显式使用 “correct rate”，未打印公式`
- 从数值可知，它等价于 precision 风格的正确率：

```text
CorrectRate = TP / (TP + FP)
```

- 文中样例：

```text
TP = 4610
FP = 172
CorrectRate = 4610 / (4610 + 172) = 96.4%
```

### 5.5 NVD 数据质量评估指标

#### 5.5.1 NVD upto-version false positive rate / false negative rate

- 论文状态：`正文显式使用`
- 年度计算口径：
  - 分母：该年 NVD 报告的 vulnerable versions 总数
  - 分子：这些版本中的 `FP` 或 `FN` 数量
- 复现公式：

```text
FP_Rate_year = FP_versions_year / NVD_reported_versions_year
FN_Rate_year = FN_versions_year / NVD_reported_versions_year
```

#### 5.5.2 NVD all-vulnerable-version-set error rate

- 论文状态：`正文显式使用`
- 对所有 vulnerable version set 也按同样方式统计：

```text
FP_Rate_all = FP_versions_all / NVD_reported_versions_all
FN_Rate_all = FN_versions_all / NVD_reported_versions_all
```

### 5.6 缺失日志记录率

- 论文状态：`正文显式使用`
- 例如文中给出 2016 年 `36 / 221 = 16%`，2018 年 `20 / 338 = 6%`
- 可复现公式：

```text
MissingChangelogRate_year = MissingRecordedPatchedCVEs_year / CVEsReleasedThatYear
```

### 5.7 人工工作量指标

#### 5.7.1 Manual inspection count

- 论文状态：`正文显式使用`
- 例如：
  - partial match 需要至少 532 次检查
  - 337 个 CVE 有 partial matches
- 复现公式：

```text
AvgChecksPerCVE = NumberOfManualChecks / NumberOfRelevantCVEs
```

#### 5.7.2 Man-hours spent

- 论文状态：`正文显式使用`
- 例如：
  - exact-matching 过程总耗时 `10.2h`
  - partial-matching 验证耗时 `3.3h`
- 复现公式：

```text
TotalManualHours = Σ_i Hours_i
AvgManualHoursPerCVE = TotalManualHours / NumberOfRelevantCVEs
```

### 5.8 与 ReDeBug / VUDDY 的对比指标

- 论文状态：`正文显式使用`
- 对五个软件随机各选一个版本，与 69 个真实漏洞对比，使用：
  - `Precision = TP / (TP + FP)`
  - `Recall = TP / (TP + FN)`
- 论文没有在这部分引入新公式。

### 5.9 对 VulnVersion 的直接启发

- TDSC 论文虽然不是 LLM 论文，但它提供了两个你很值得保留的视角：
  - `lower-bound recall`
  - `manual verification workload`
- 这对处理“证据不足”“部分可疑但未能完全确认”的版本特别有用。

## 6. 四篇论文的交叉对照

### 6.1 哪些指标是四篇论文共同或高度重合使用的

#### 6.1.1 共同核心

- `Precision`
- `Recall`
- `F1`

说明：

- `How far are we` 与 `CaVulner` 用在 `version-level`
- `AgentSZZ` 用在 `BIC-set level`
- `TDSC` 用在版本识别和工具对比

#### 6.1.2 受影响版本识别论文共同核心

- `CVE-level Accuracy`
- `Version-level Precision`
- `Version-level Recall`
- `Version-level F1`

#### 6.1.3 只有部分论文使用

- `No-Miss Ratio (NMR)`：只在 `How far are we`
- `Krippendorff's alpha`：`CaVulner`
- `Cohen's Kappa`：`How far are we`
- `Runtime / Tokens / Cost / Turns`：`AgentSZZ`、`CaVulner`
- `Lower-bound Recall`：`TDSC`
- `Correct rate`：`TDSC`

### 6.2 哪些指标对 VulnVersion 最值得直接落地

如果你的目标是后续严格评测 VulnVersion，我建议最低限度保留以下九项：

1. `CVE-level Accuracy`
2. `CVE-level No-Miss Ratio`
3. `Version-level Precision`
4. `Version-level Recall`
5. `Version-level F1`
6. `AvgInputTokensPerCVE`
7. `AvgOutputTokensPerCVE`
8. `AvgCostPerCVE`
9. `AvgTimePerCVE`

再往上，强烈建议再加：

10. `Execution failure rate`
11. `Timeout rate`
12. `Subset F1 / Recall`
13. `Lower-bound recall`
14. `Manual review workload`

## 7. 可直接复用到 VulnVersion 的统一计算方案

这一节不是某一篇论文原封不动的公式，而是把四篇论文实际用过的指标统一成一套可以直接落地到 VulnVersion 的评测模板。

### 7.1 主效果指标

#### 7.1.1 CVE-level Accuracy

```text
Accuracy_CVE =
Σ_i 1[Pred_i = GT_i] / N
```

#### 7.1.2 CVE-level No-Miss Ratio

```text
NMR =
Σ_i 1[GT_i ⊆ Pred_i] / N
```

#### 7.1.3 Version-level Precision / Recall / F1

```text
TP_v = Σ_i |GT_i ∩ Pred_i|
FP_v = Σ_i |Pred_i \ GT_i|
FN_v = Σ_i |GT_i \ Pred_i|

Precision_v = TP_v / (TP_v + FP_v)
Recall_v = TP_v / (TP_v + FN_v)
F1_v = 2 * Precision_v * Recall_v / (Precision_v + Recall_v)
```

### 7.2 资源指标

#### 7.2.1 Token

```text
AvgInputTokensPerCVE = Σ_i InputTokens_i / N
AvgOutputTokensPerCVE = Σ_i OutputTokens_i / N
AvgTotalTokensPerCVE = Σ_i (InputTokens_i + OutputTokens_i) / N
```

#### 7.2.2 Cost

```text
Cost_i =
(InputTokens_i / 10^6) * PriceInputPer1M
+ (OutputTokens_i / 10^6) * PriceOutputPer1M

AvgCostPerCVE = Σ_i Cost_i / N
```

#### 7.2.3 Time

```text
AvgTimePerCVE = Σ_i Time_i / N
```

#### 7.2.4 Turn / density

```text
AvgTurnsPerCVE = Σ_i Turns_i / N
AvgTokensPerTurn = Σ_i (TotalTokens_i / Turns_i) / N
```

### 7.3 稳定性与执行链指标

这部分不是四篇论文共同使用的标准项，但按照 AgentSZZ 和 TDSC 的思路，你后续非常应该加上。

#### 7.3.1 Execution failure rate

```text
ExecutionFailureRate =
NumberOfCasesWithExecutionFailure / NumberOfAllCases
```

#### 7.3.2 Timeout rate

```text
TimeoutRate =
NumberOfTimeoutCases / NumberOfAllCases
```

#### 7.3.3 Lower-bound Recall

当存在“不确定版本/不确定 case”时，可保守计算：

```text
LowerBoundRecall =
TP / (TP + FN_confirmed + FN_uncertain_worst_case)
```

### 7.4 子集评估

对以下任意子集 `S`，都应重复计算 7.1 与 7.2 中的主指标：

- repo 子集
- patch type 子集
- single-branch / multi-branch 子集
- hard case 子集
- timeout-prone 子集
- LLM infer-heavy 子集

统一写法：

```text
Metric(S) = 在 i ∈ S 上按原公式重算
```

## 8. 最终结论

- 四篇论文最稳定、最可复用的主指标组合不是 `CVE-level F1`，而是：
  - `CVE-level Accuracy`
  - `CVE-level No-Miss Ratio`
  - `Version-level Precision`
  - `Version-level Recall`
  - `Version-level F1`
- 如果 VulnVersion 只报一个总 F1，很难与这些论文对齐。
- 如果 VulnVersion 用 LLM/Agent，必须补充：
  - `Input / Output / Total Tokens`
  - `Cost`
  - `Runtime`
  - `Turns`
- 如果 VulnVersion 存在“无法完全确认”的 case，建议引入 TDSC 风格的：
  - `Lower-bound Recall`
  - `Manual review workload`
- 如果 VulnVersion 想说明方法在难例上的价值，建议引入 AgentSZZ 风格的：
  - `challenging-subset recall`
  - `relative improvement`
- 如果 VulnVersion 想避免“整条版本区间没圈准却看起来 F1 不差”的问题，必须同时报告：
  - `CVE-level Accuracy`
  - `CVE-level NMR`
  - `Version-level F1`
