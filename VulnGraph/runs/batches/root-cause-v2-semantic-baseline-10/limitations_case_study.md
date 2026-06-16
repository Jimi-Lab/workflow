# Agentic-SZZ、MAS-SZZ 与 VulnGraph Root Cause Agent 实测优点、局限性与 Case Study

## 1. 分析边界

本文只依据当前本地代码与实际运行结果，不以论文中的理想化描述替代运行证据。

分析对象分为三个阶段不同的方法：

1. **Agentic-SZZ**：从修复提交出发，基于 blame、时序知识图谱和 Agent 搜索输出 BIC。
2. **MAS-SZZ**：先分析补丁根因和漏洞语句，再对语句执行迭代 blame，输出一个或多个 BIC。
3. **VulnGraph Root Cause Agent v2 semantic baseline**：当前只完成修复语义、谓词和代码锚点抽取，尚未运行 Judge Agent、BIC 判定和受影响版本转换。

因此，三者不能只用一个指标直接排序：

- Agentic-SZZ 和 MAS-SZZ 可评价 BIC 转换后的 affected-version 指标。
- 当前 VulnGraph baseline 只能评价根因语义、锚点和证据契约，不能宣称其 BIC 或 affected-version 性能。

还需要区分两类问题：

- **方法论局限**：即使实现无 bug，方法的基本假设仍会造成系统性误差。
- **实现/运行局限**：由候选截断、异常处理、schema、fallback 或工程策略造成，原则上可通过修改实现修复。

## 2. 实际结果总览

### 2.1 BIC 到受影响版本的 30-CVE 结果

| 方法 | 版本转换口径 | BIC 覆盖率 | Micro-P | Micro-R | Micro-F1 | Macro-F1 | CVE 完全正确率 |
|---|---|---:|---:|---:|---:|---:|---:|
| Agentic-SZZ | 纯拓扑 | 83.33% | 56.59% | 30.00% | 39.21% | 65.36% | 43.33% |
| MAS-SZZ | 纯拓扑 | 96.67% | 65.22% | 78.93% | 71.42% | 76.41% | 50.00% |
| Agentic-SZZ | latest-FIC 时间约束 | 83.33% | 99.66% | 28.81% | 44.69% | 64.21% | 43.33% |
| MAS-SZZ | latest-FIC 时间约束 | 96.67% | 93.66% | 78.33% | 85.31% | 76.82% | 46.67% |

这些结果表明：

- Agentic-SZZ 的主要问题是**漏报**，不是无界误报。时间约束几乎消除了 FP，但 Recall 仍只有 28.81%。
- MAS-SZZ 的优势主要来自更高的输出覆盖率和更早/更多的候选 BIC，而不是每个 BIC 都更接近真实语义引入点。
- CVE 完全正确率仍不足 50%，说明较高的 Micro-F1 会被“大版本集合 case”主导，不能替代 vulnerability-level exact match。
- 本地 Linux 仓库被检测为 shallow；涉及 Linux 的正式数字必须在完整历史仓库上复跑。

还要注意原生输出不能直接作为本数据集的 accuracy：Agentic-SZZ 结果中的 `ground_truth` 数组为空，因此其原生 `success=false` 不表示 BIC 错误；MAS-SZZ 结果中的 `ground_truth_bic` 同样为空。上表使用统一 BIC-to-version adapter，将预测 BIC 转换到论文清洗后的 release universe 后再与 `affected_version` 比较。

### 2.2 VulnGraph 10-CVE Root Cause 语义结果

| 指标 | 全部 10 个 case | 仅结构接受的 8 个 case |
|---|---:|---:|
| 整体根因正确率 | 6/10 = 60.0% | 6/8 = 75.0% |
| 锚点命中相关修复 hunk | 8/10 = 80.0% | 7/8 = 87.5% |
| evidence link 精确 | 4/10 = 40.0% | 4/8 = 50.0% |
| unsupported inference rate | 6/10 = 60.0% | 6/8 = 75.0% |
| multi-fix 结构覆盖 | 2/2 = 100.0% | - |
| multi-fix 语义覆盖 | 1/2 = 50.0% | - |

核心现象是：**模型较容易找到大致正确的文件/hunk，却不容易建立严格、最小、逐项可验证的因果证据。**

## 3. 各方法经过实际测试证明的优点

本节只记录当前本地实验能够支持的优势，不把论文设计目标直接当作实验结论。

### 3.1 实测优势汇总

| 方法 | 已被当前实验支持的优势 | 直接证据 | 最适合复用的能力 |
|---|---|---|---|
| Agentic-SZZ | 在可 blame、分支局部且候选集较集中的 case 上精度高；能够沿结构化历史继续探索 | latest-FIC Micro-P 99.66%；13/30 exact；`CVE-2020-11984` 14/14 exact | 结构化历史候选图、branch-local commit 检索、受限候选搜索 |
| MAS-SZZ | 输出覆盖率、召回率、add-only 和多锚点处理明显优于 Agentic-SZZ | BIC coverage 96.67%；latest-FIC Micro-R 78.33%、F1 85.31%；add-only topology mean F1 94.3% | 根因到 pre-fix statement 的语义桥接、top-k 多角色锚点 |
| VulnGraph Root Cause Agent | 对补丁机制、谓词和 hunk 的结构化解释较强，且结果可审计 | accepted-only 根因正确率 75%；anchor hunk precision 87.5%；结构 multi-fix coverage 2/2 | 证据契约、结构化 root-cause packet、失败分层和可追踪 artifacts |

### 3.2 Agentic-SZZ 的实测优点

#### A+1. 在候选历史较清晰时能够得到很高的版本精度

应用 latest-FIC 时间边界后，Agentic-SZZ 的 Micro-Precision 达到 **99.66%**。这说明它一旦选择了位于正确 release lineage 上的 BIC，通常不会大量引入修复后的版本。其问题主要是 FN，而不是输出区间完全失控。

30 个 case 中有 13 个 affected-version 集合完全正确。例如：

- `CVE-2020-11984`：输出 2.4 分支上的等价引入提交，得到 TP=14、FP=0、FN=0。
- `CVE-2020-8231`：得到 TP=62、FP=0、FN=0。
- `CVE-2020-14212`：得到 TP=1、FP=0、FN=0。
- `CVE-2020-11869`：在 latest-FIC 口径下得到 TP=3、FP=0、FN=0。

因此 Agentic-SZZ 不是“整体不可用”，而是对 case 类型敏感：当漏洞相关旧行存在、blame 候选少、分支局部提交可达 release tags 时，它可以非常精确。

#### A+2. 结构化历史扩展能比单语句追踪找到更早的分支局部候选

在 `CVE-2020-15466` 上，MAS-SZZ 从直接控制语句得到的 BIC 只恢复 12/244 个 GT 版本；Agentic-SZZ 通过历史扩展恢复 76/244。两者都不完整，但 Agentic-SZZ 证明了文件、函数和祖先 commit 搜索能够越过当前行的最后一次修改，找到更早的相关历史。

这一能力适合复用到你的 **candidate generation** 阶段，而不应直接作为最终 BIC 判定器。

#### A+3. 简单 case 的 fast path 成本较低

`CVE-2020-11984` 的成功运行只使用 4,643 input tokens、5 个 agent steps，约 7.65 秒。说明 single/dominant blame 等排序信号在简单 case 中可以作为有效的成本优化。

需要保留的是“优先级信号”，而不是原实现中的强制 `STOP`。你的 Judge 仍应检查 candidate 与 parent 的漏洞语义转变。

#### A+4. 输出包含较完整的搜索成本与轨迹信息

Agentic-SZZ 记录 blame、TKG、Agent 各阶段耗时，以及 token、step、confidence 和候选轨迹。即使其异常状态还不够细，这些字段仍适合用于：

- 分析搜索成本与准确率的关系；
- 比较 fast path 和 full search；
- 建立候选预算与停止策略；
- 在论文中报告效率，而不只报告最终 F1。

### 3.3 MAS-SZZ 的实测优点

#### M+1. 输出覆盖率和召回率明显更高

MAS-SZZ 在 30 个 case 中有 29 个输出 BIC，覆盖率为 **96.67%**；Agentic-SZZ 为 83.33%。在 latest-FIC 口径下：

- MAS-SZZ Micro-Recall：**78.33%**；
- Agentic-SZZ Micro-Recall：28.81%；
- MAS-SZZ Micro-F1：**85.31%**；
- Agentic-SZZ Micro-F1：44.69%。

这说明“先解释根因，再定位父版本漏洞语句”的流程确实缓解了传统 deleted-line blame 的候选缺失问题。

#### M+2. 对 add-only 修复的处理经过实验验证明显更有效

5 个 add-only case 中：

| 口径 | MAS-SZZ Mean per-CVE F1 | Exact | BIC coverage |
|---|---:|---:|---:|
| topology-only | 94.3% | 4/5 | 5/5 |
| latest-FIC | 78.5% | 3/5 | 5/5 |

对应的 Agentic-SZZ topology-only mean F1 为 64.8%，latest-FIC 为 46.5%。这支持 MAS-SZZ 的核心优点：它不是 blame 新增 guard，而是尝试定位 guard 所保护的父版本旧语句。

`CVE-2020-19667` 是直接例子：Agentic-SZZ 输出空 BIC，而 MAS-SZZ 输出两个候选并恢复 208/208 个 GT 版本。

#### M+3. Top-k、多语句锚点可以覆盖分散的漏洞机制

`CVE-2020-8231` 的 UAF 涉及 pointer state 和 connection lifecycle。MAS-SZZ 从两个漏洞语句得到两个 BIC，union 后恢复 62/62 个版本。这证明对跨位置漏洞保留多个语义锚点，比强制压缩成唯一 top-1 更可靠。

你的系统应学习其“保留 top-k”能力，但进一步为每个 anchor 标注 `state_write`、`lifecycle_free`、`unsafe_use` 等语义角色，避免无约束 union。

#### M+4. 根因描述通常具有较好的可解释性

多个实际 case 中，MAS-SZZ 在 BIC 错误或不完整的情况下，根因文本仍然正确：

- `CVE-2020-11984`：正确识别 16-bit `pktsize` 截断及上界检查缺失。
- `CVE-2021-23840`：正确识别 EVP output length 超过 `INT_MAX`。
- `CVE-2020-15466`：正确识别 `if (tree)` 导致 offset 不前进和无限循环。
- `CVE-2020-8231`：正确识别 dangling `lastconnect` pointer。

这说明 MAS-SZZ 最值得迁移的是 **root cause -> vulnerable statements** 的语义桥接，而不是其最终的单行迭代 blame 规则。

#### M+5. 对 Agentic-SZZ 空结果具有互补性

Agentic-SZZ 在 `CVE-2020-19667`、`CVE-2022-0171`、`CVE-2020-15389` 和 `CVE-2020-13164` 等 case 输出空 BIC；MAS-SZZ 在其中多个 case 能继续生成候选。以 `CVE-2022-0171` 为例，MAS-SZZ 即使走 fallback，仍得到 TP=8、FP=1、FN=0。

因此两种方法的关系不是简单替代：MAS-SZZ 更适合提高 anchor/candidate recall，Agentic-SZZ 的历史图更适合扩展和组织候选。

### 3.4 VulnGraph Root Cause Agent 的实测优点

#### V+1. 对已通过结构契约的 case，根因语义正确率较高

8 个 `ingested_raw` case 中有 6 个整体根因正确，即 **75%**。正确 case 覆盖多种漏洞类型：

- `CVE-2022-0286`：NULL dereference，且是 add-only guard。
- `CVE-2020-15389`：跨循环迭代 stale pointer/double-free。
- `CVE-2020-1967`：OpenSSL NULL dereference。
- `CVE-2020-13164`：递归深度/可能文件系统循环。
- `CVE-2020-8231`：connection lifecycle UAF。
- `CVE-2020-11984`：整数宽度和显式上界约束。

这说明当前 packet 中的 patch、函数、证据和结构约束足以支持不同漏洞机制，不是只对某一种 CWE 有效。

#### V+2. 能够把自然语言根因拆成可执行的谓词和代码锚点

当前输出不是单段 explanation，而是区分：

- vulnerable predicate；
- fix predicate；
- code anchor；
- hypothesis；
- evidence link。

这种结构非常适合连接后续 Judge Agent。例如 `CVE-2022-0286` 准确给出“`slave` 可能为 NULL”和“使用 `slave->dev` 前必须非 NULL”的前后谓词，可以直接转化为 candidate/parent transition test。

#### V+3. 对相关修复 hunk 的定位能力较强

全 10-case anchor hunk precision 为 **80%**，结构接受 case 为 **87.5%**。说明模型大多数时候能够把根因落到正确文件和修复区域，而不是只复述 CVE 描述。

这为后续生成 pre-fix anchors 提供了较好的起点：先找对 fix hunk，再通过 guard-to-use、definition-use 和 call-chain 映射到父版本旧代码。

#### V+4. 能显式表示 multi-fix，并暴露“结构覆盖与语义覆盖”的差异

两个 multi-fix case 在结构层均被识别，structural coverage 为 2/2；人工语义复核发现真正完整的只有 1/2。这虽然暴露了局限，但也是架构优点：系统保留 fix-set、hunk 和 anchor 的对应关系，使研究者能够测量 semantic coverage，而不是只看到一个最终 BIC。

#### V+5. 严格契约和逐阶段 artifacts 提供了较强可审计性

每个 case 保存 `prompt.txt`、`raw_response.txt`、`parsed_output.json`、`ingestion_result.json`、`contract_lint.json`/`parse_error.json` 和 `evidence_trace.json`。因此可以明确区分：

- 模型没有理解漏洞；
- 模型理解了但 JSON/schema 错误；
- anchor 找对但 function binding 不完整；
- 结构通过但 evidence link 不充分。

`CVE-2022-0171` 和 `CVE-2020-19667` 正是通过这些 artifacts 被诊断为可修复契约失败，而不是含糊地记为“LLM 错误”。这对论文 failure taxonomy 和系统调试都很重要。

### 3.5 三种方法的互补关系

当前实验最支持的组合不是结果投票，而是阶段级复用：

1. **VulnGraph**：生成可审计的漏洞机制、谓词、fix hunk 和证据关系。
2. **MAS-SZZ 思路**：把修复语义映射为 top-k pre-fix vulnerable statements，尤其处理 add-only。
3. **Agentic-SZZ 思路**：围绕已接受 anchors 构造结构化历史候选图，扩展 line blame 的局部结果。
4. **你的 Judge Agent**：比较候选 commit 与 parent，判断漏洞谓词是否首次成立。
5. **branch-aware converter**：把 canonical/branch-local BIC cluster 转换为 release versions。

这种组合同时保留了三者已经实测有效的能力，并针对各自失败点增加独立验证层。

## 4. 共同的方法论局限

### 4.1 `git blame` 回答的是最后修改者，不是漏洞引入者

对修复前语句执行 blame，只能得到当前文本行的最后一次修改提交。它不能自动识别：

- 漏洞是否由更早的设计决策引入；
- 当前行是否只是重构、移动或 backport 的产物；
- 漏洞是否由多个文件、多个状态变量或缺失检查共同构成；
- 漏洞是否来自“没有代码”的缺失行为。

因此，`blame(line) = BIC` 是不可成立的强假设。Agent 或知识图谱只能扩展搜索空间，不能从理论上消除“line ownership 与 semantic introduction 不等价”的问题。

### 4.2 从补丁推断根因存在 `patch-as-cause bias`

修复提交同时包含：

- 真正阻断漏洞的必要条件；
- 防御性检查；
- 类型清理；
- 日志、错误码和 UI plumbing；
- 重构或生成文件变化。

模型容易把“补丁改了什么”全部解释为“漏洞为什么发生”。这会产生看似完整、实际过宽的根因，并把无关 hunk 送入 blame。

### 4.3 单一 BIC 到连续版本区间的映射忽略分支与 backport

真实项目历史不是一条线：

- 主干可能先引入功能；
- 稳定分支随后 cherry-pick/backport；
- 修复也可能先落主干，再分别回移到多个 release branch；
- 某些标签不是所选 BIC 的后代，但包含语义等价的漏洞代码。

所以“从一个 BIC 到一个 FIC 取所有标签”的区间假设，在复杂分支项目中不充分。必须识别 branch-local introduction 和 patch-equivalent commits。

### 4.4 affected-version 数据不能唯一监督 BIC

当前数据集给的是 affected versions 和 fixing commits，不是人工标注的唯一 BIC。多个不同提交可能诱导出相同 release 边界：

- 某个主干引入提交；
- 某个稳定分支 backport；
- 一个位于相邻 release tag 之间的更早或更晚提交。

因此不能仅凭 affected-version F1 断言“BIC 找对了”。论文中应分别报告：

1. 根因语义是否正确；
2. 候选是否包含真实引入机制；
3. 转换后的版本集合是否正确。

### 4.5 缺少显式不确定性和拒答状态

三个流程都倾向于把不完整证据压缩成一个肯定结果：

- Agentic-SZZ 在 Agent 失败时退化到 top blame；
- MAS-SZZ 在最大深度或第一步 no-vuln 时仍返回一个 BIC；
- Root Cause Agent 会在证据不充分时生成完整机制和高置信度谓词。

正确做法应保留 `insufficient_evidence`、`ambiguous_boundary`、`branch_mapping_required`、`schema_repaired` 等状态，而不是把工程失败或证据不足当作预测结果。

## 5. Agentic-SZZ 的局限性

### 5.1 方法论局限

#### A1. 初始 blame 锚点一旦错，图搜索只会扩大错误邻域

Agentic-SZZ 强于普通 SZZ 的部分是沿文件、函数和 commit 历史扩展候选。但知识图谱并不提供漏洞语义真值。若初始锚点是重构行、错误处理行或补丁上下文，后续检索仍围绕错误对象展开。

#### A2. 单一 blame 提交被赋予过强先验

代码明确对 single-blame 输出 `STOP! Return this SHA as BIC`。这等价于假设“只有一个行所有者时，不需要语义边界验证”。但 single blame 只能说明这些行同属一个最后修改提交，不能说明该提交使漏洞从不存在变成存在。

#### A3. Add-only 的上下文 blame 是空间邻近启发式

当整个修复提交没有删除行时，代码从新增行附近取父版本 context line，再把这些行当作待 blame 的 `deleted_lines`。这对简单 null-check case 有效，但其理论依据只是文本邻近：

- 新增检查可能保护远处状态或跨函数调用；
- 根因可能是某个旧定义、状态转换或生命周期事件；
- 新文件会被直接跳过。

因此它没有真正解决 add-only，只是把“无删除行”转换成“附近旧行”。

#### A4. 搜索成本随历史复杂度剧烈波动

实际运行中，一个 httpd case 使用 1,714,355 input tokens、61 个 agent steps、约 84.8 秒。说明图搜索没有稳定的证据预算与停止准则。更大的搜索轨迹不必然带来更正确的 BIC。

### 5.2 实现/运行局限

#### A5. 新增文件被跳过

`blame.py` 对 `diff.a_path is None` 直接 `continue`。若漏洞修复通过新增验证文件、替换实现或新建模块完成，Agentic-SZZ 不会为该文件构造初始证据。

#### A6. 候选截断与 top-candidate fallback 会掩盖失败

系统只向 Agent 暴露 top-K 候选；Agent 异常时返回 `candidates[0]`，置信度 0.3。这样输出中同时混合了“语义判定结果”和“系统失败后的猜测”。

#### A7. 异常路径会产生空 BIC，且缺乏阶段级错误状态

30 个 case 中有 5 个空 BIC：`CVE-2020-13904`、`CVE-2020-19667`、`CVE-2022-0171`、`CVE-2020-15389`、`CVE-2020-13164`。其中多个 case 耗时 70-110 秒，但最终 token 和 step 均为 0。结果只表现为 empty BIC，无法区分图构建失败、Agent 未启动、候选为空或解析失败。

## 6. MAS-SZZ 的局限性

### 6.1 方法论局限

#### M1. 根因文本正确不代表漏洞语句是正确的历史锚点

MAS-SZZ 能生成比纯 blame 更合理的漏洞解释，但后续仍要把抽象根因压缩为少量具体语句。一个语句可以准确描述“修复前缺陷表现”，却是很晚才出现的实现行，而不是最早引入该漏洞机制的语句。

#### M2. 单语句迭代 blame 无法表达 feature-level introduction

漏洞可能由多个位置共同构成，例如：状态写入、生命周期释放、缺失有效性检查和最终使用点。逐行向前追踪会把问题拆成多个局部 line history，难以确定哪一组提交共同形成了可利用状态。

#### M3. 多 BIC union 提高召回，但会混合不同语义角色

MAS-SZZ 对多个漏洞语句分别追踪并输出多个 BIC。在 `CVE-2020-8231` 上这是优势；但一般情况下，这些提交可能分别对应定义、重构、backport 和真正引入。直接 union 版本区间缺少角色分类和分支约束，容易产生 FP。

#### M4. Root Cause reviewer 不是独立验证器

运行结果中 29/29 可用 case 的 root cause review 均通过。结合 reviewer 的宽松解析规则，这说明 reviewer 的区分度不足。使用同类模型、同一补丁证据进行自审，也存在强相关错误，不能视为独立裁判。

### 6.2 实现/运行局限

#### M5. 第一跳判断为“无漏洞”时仍返回该提交

`bic_agent.py` 中若第一步 `not exists` 且没有 `prev_commit`，代码仍返回当前 blame commit，并标记 `first step no-vuln`。按方法定义，此时最多能说明初始锚点或判断过程失败，不能将“无漏洞提交”作为 BIC。

#### M6. 达到 20 层深度时把截断结果伪装成 BIC

达到 `MAX_TRACE_DEPTH = 20` 后，系统返回 `prev_commit or blame_commit` 并记录 `bic_found`。这是右删失，不是边界发现。应输出 `depth_limit_reached`，保留候选区间，而不是肯定 BIC。

#### M7. 非 JSON 输出通过字符串否定词猜测漏洞存在性

解析失败时，`exists = "not exist" not in reply.lower()`。这会被措辞、双重否定、解释性文本和模型格式漂移轻易破坏。

#### M8. 无漏洞语句时的 lexical fallback 会选择非代码根因锚点

fallback 从根因文本提取标识符，对删除行做 substring 计数并取 top 3。它不理解文件角色、语句类型、数据流或控制流，因此错误码表、生成文件和文档行也可高分。

## 7. VulnGraph Root Cause Agent 的局限性

### 7.1 方法论局限

#### V1. 当前主要识别“修复语义”，还没有完成“历史引入语义”

当前输出的 code anchors 大多位于修复 hunk。它们适合解释 fix predicate，但不一定是应该在 `C_fix^1` 上 blame 的 pre-fix semantic anchors。若直接把全部修复 hunk 送入 blame，会复制 MAS-SZZ 的 patch-to-anchor 偏差。

#### V2. 结构化输出完整不等于证据闭环完整

`CVE-2020-14212` 同时包含两个 fix commit，结构门判断 fix set 完整，但语义锚点只覆盖顶层 `dnn_backend_native.c`，遗漏多个 layer loader 的 operand guard hunk。结构 multi-fix coverage 为 100%，语义 multi-fix coverage 只有 50%。

#### V3. 模型容易把所有修复动作升级为根因

`CVE-2020-11869` 中，模型把 bpp/stride 检查、坐标类型变化和坐标更新逻辑全部解释为除零、OOB、整数溢出/下溢根因。补丁只证明这些防御动作被加入，并没有逐项证明所有宣称的漏洞触发机制。

#### V4. 证据引用仍偏“相关性”，缺少 claim-level entailment

10-CVE 中 anchor hunk 命中率达到 80%，但 evidence link precision 只有 40%。这说明“锚点在相关 hunk”不足以证明“该 hunk 支持这个具体谓词”。每个 root-cause claim 应绑定最小证据和推理关系，而不是共享一组宽泛 evidence IDs。

### 7.2 实现/运行局限

#### V5. 可修复的 schema 缺失被当作语义失败

`CVE-2022-0171` 的 raw response 是语义合理的 fenced JSON，描述了 SEV guest memory 回收后的 cache incoherency，并给出五个 anchors；其中四个仅缺 `path`。Pydantic 校验失败后整个 case 记为 parse error。

#### V6. function binding gate 会级联删除正确证据

`CVE-2020-19667` 的 anchor 指向正确的 `ReadXPMImage` 和新增 `memset` hunk，但因缺 `function_id` 被拒绝，随后 predicates 和 hypothesis 因引用 rejected anchor 一起失败。这里失败的是契约绑定，不是模型完全没找到根因。

#### V7. unsupported inference 缺少强制降权

10 个 case 中 6 个存在 unsupported inference，但输出仍可维持高 confidence。当前 confidence 更像模型自信程度，不是证据覆盖率的函数。

## 8. 代表性 Case Study

### Case 1: CVE-2020-11984 - 语义 BIC 与 release-branch BIC 冲突

**现象**

- MAS-SZZ 输出 `da54e90d...`，对应主干中的 UWSGI 机制引入，根因解释正确。
- 该提交不是数据集 2.4 release tags 的祖先，版本转换状态为 `bic_reaches_no_release`，14 个 GT 版本全部漏掉。
- Agentic-SZZ 输出 `99c59e09...`，对应 2.4 分支中的等价回移提交，得到 TP=14、FP=0、FN=0。

**方法论结论**

一个“全局语义上最早”的 BIC 不一定是 affected-version 任务需要的 branch-local boundary。受影响版本识别必须维护：

- canonical introduction；
- branch-local equivalent introduction；
- fix/backport equivalence；
- tag 所在分支与可达性。

**适合论文的 claim**

> BIC identification and affected-version boundary identification are related but non-equivalent tasks under branched histories.

### Case 2: CVE-2020-27814 - 两个方法共同把修复系列提交当作 BIC

**现象**

- Agentic-SZZ 与 MAS-SZZ 都输出 `649298dc...`。
- 该提交的语义是再次扩大 encoder buffer，属于修复系列中的前序 patch，紧邻最终 FIC。
- BIC-FIC 之间没有对应受影响 release，得到 TP=0、FN=5。

**根因**

- blame 找到了“最后修改同一分配表达式的提交”；
- 两种方法都缺少 fix-series / partial-fix detection；
- 候选与 FIC 过近并不会自动触发“它可能也是修复”的反证检查。

**改进**

对每个候选执行三态判定，而不是只问 has_bug：

1. `introduces_bug`；
2. `preserves_bug`；
3. `partially_fixes_or_hardens`。

同时检查 commit message、issue reference、与 FIC 的 patch similarity 和同一 pull request/series 关系。

### Case 3: CVE-2020-15466 - 根因正确，但语句锚点太晚

**现象**

- MAS-SZZ 正确识别 `if (gvcp_telegram_tree != NULL)` 导致 offset 不更新和无限循环。
- 其 BIC `1e630b42...` 只恢复 12/244 个受影响版本，Recall=4.92%。
- Agentic-SZZ 选择更早的 `e7e4dc5...`，恢复 76/244，仍然只有 31.15% Recall。

**方法论结论**

修复前的直接控制语句是 vulnerability manifestation anchor，但不一定是 feature introduction anchor。Judge Agent 应允许沿函数创建、循环结构形成、条件引入和代码移动继续搜索，而不是在当前语句首次出现处停止。

### Case 4: CVE-2021-23840 - 正确根因被错误 fallback 锚点摧毁

**现象**

- MAS-SZZ 的根因正确识别 EVP output length 超过 `INT_MAX` 的整数溢出。
- 漏洞语句提取为空，触发 `deleted_line_vote`。
- fallback 选出的 top 3 全部来自 `crypto/err/openssl.txt` 的旧错误字符串，而不是 `crypto/evp/evp_enc.c` 的长度计算。
- 最终 BIC `5816586...` 只得到 10/32 GT，纯拓扑时还产生 56 个 FP。

**方法论/实现结论**

补丁相关文件不等于可 blame 的漏洞文件。fallback 必须先做文件角色分类，过滤文档、错误表、生成文件、测试和纯声明 hunk，再进行数据流/控制流相关性排序。

### Case 5: CVE-2020-14212 - fix-set 完整不等于语义完整

**现象**

- VulnGraph 正确识别 operand index 必须小于 `network->operands_num`。
- 输出声明覆盖两个修复提交，但 code anchors 只覆盖顶层 backend hunk。
- conv2d、depth2space、mathbinary、mathunary、maximum、pad 等 loader 中的索引 guard 未被锚定。

**结论**

multi-fix 评估至少需要三层 coverage：

1. commit-set coverage；
2. root-cause hunk coverage；
3. independent vulnerable-location coverage。

只统计 fix commit ID 会高估系统对多位置漏洞的理解。

### Case 6: CVE-2020-11869 - patch aggregation 导致过宽根因

**现象**

- VulnGraph 与 MAS-SZZ 都把 QEMU ATI patch 的多个变化合并成大范围的整数溢出、除零、OOB 机制。
- 实际补丁证明 bpp/stride zero checks、无符号坐标和条件坐标更新，但不能逐项证明所有推断都是漏洞触发条件。
- 受影响版本上 Agentic-SZZ latest-FIC 为 3/3 exact；MAS-SZZ 为 TP=3、FP=2。最终版本结果较好，不能反向证明其根因解释严格正确。

**结论**

这是一个重要反例：**affected-version 指标正确可能掩盖 root-cause hallucination。** 论文必须分层评价，而不能只报告最终版本 F1。

### Case 7: CVE-2022-0171 与 CVE-2020-19667 - 结构失败和语义失败被混为一类

**现象**

- `CVE-2022-0171`：四个 anchor 缺 `path`，其余语义证据较强，整体被记为 parse error。
- `CVE-2020-19667`：缺 `function_id` 导致 anchor、predicate、hypothesis 级联拒绝。
- Agentic-SZZ 在这两个 case 都输出空 BIC；MAS-SZZ 则有结果，其中 `CVE-2022-0171` 使用 fallback 后达到 8 TP、1 FP。

**结论**

需要把状态拆为：

- `semantic_failure`；
- `schema_failure_repairable`；
- `binding_failure_repairable`；
- `candidate_generation_failure`；
- `history_search_failure`。

否则 case study 会错误地把工程契约问题归因于模型推理能力。

### Positive Control 1: CVE-2022-0286 - Add-only 可以通过“旧使用点”解决

修复新增 `if (!slave)`，但可 blame 的根因不是新增 guard，而是父版本已有的：

```c
slave = rcu_dereference(bond->curr_active_slave);
slave->dev
```

这个 case 证明 add-only 的正确策略不是“blame 新增行”，而是从新增谓词反推其保护的旧值、旧 use 和缺失的不变量：

1. 新 guard 的 predicate 是 `slave != NULL`；
2. 在父版本定位 guard 控制下的第一个危险 use `slave->dev`；
3. 回溯 `slave` 的定义 `rcu_dereference(...)`；
4. 将 definition-use pair 作为 top-k blame anchors；
5. Judge 候选提交前后是否首次形成“可为空值 + 无检查使用”。

### Positive Control 2: CVE-2020-8231 - 多语义锚点优于单一 top-1

MAS-SZZ 从 pointer assignment 和 pointer state 两个语句得到两个 BIC，union 后恢复 62/62 版本。该 case 支持保留 top-k anchors，但不能简单 union：每个 anchor 应标注 semantic role，例如 `state_write`、`lifecycle_free`、`unsafe_use`、`missing_validation`。

## 9. 对拟议方法的直接设计要求

### 9.1 Root Cause Agent 输出的不是“补丁行”，而是 top-k pre-fix semantic anchors

每个 anchor 至少包含：

- `role`: source / state_write / validation / lifecycle / sink / unsafe_use；
- `pre_fix_path`、`pre_fix_function`、`pre_fix_line_range`；
- `protected_by_added_guard` 或 `modified_by_fix_hunk`；
- `claim_id` 和最小 supporting evidence；
- `blame_strategy`: line / range / function-origin / callsite / definition-use；
- `confidence` 必须由 evidence coverage 计算，而不是模型自报。

### 9.2 Add-only 需要 guard-to-use、definition-use 和 invariant reconstruction

建议为 add-only 建立专门流程：

1. 解析新增 guard、初始化、清理或同步操作；
2. 在 `C_fix^1` 上计算 guard 所保护的旧代码区域；
3. 提取变量定义、危险 use、状态写入和跨函数调用；
4. 生成 top-k 旧代码 anchors；
5. 对每个 anchor 使用 blame/函数历史/调用历史生成候选；
6. Judge 比较候选 `C_j` 与 parent，判定漏洞不变量是否首次被破坏。

### 9.3 Judge Agent 必须判断“语义状态转变”，而不是代码相似度

对候选 `C_j` 和 parent `C_j^1`，输出至少四态：

- `introduced`：parent 不满足漏洞谓词，commit 后满足；
- `preserved`：前后都满足，只是修改了表达；
- `fixed_or_hardened`：commit 后漏洞减弱或消失；
- `insufficient`：证据不足。

只有 `introduced` 可作为 BIC。`preserved` 应继续追踪；`fixed_or_hardened` 用于排除 fix-series 假 BIC。

### 9.4 BIC 与版本转换之间增加 branch-aware adapter

adapter 应维护：

- canonical BIC；
- patch-id/semantic-equivalent branch BICs；
- 每个 release tag 的 branch lineage；
- 每个分支上的 fixing commit 或 patch-equivalent fix；
- 区间合并和版本规则过滤。

### 9.5 评估必须分层

建议至少报告：

| 层次 | 指标 |
|---|---|
| Root cause | mechanism accuracy、predicate precision、unsupported inference rate |
| Anchor | file/function/hunk precision、pre-fix anchor precision、anchor recall@K |
| Candidate | candidate recall@K、fix-series rejection rate、branch-equivalent recall |
| Judge | transition classification accuracy、abstention calibration |
| Version | Micro-P/R/F1、Macro-F1、CVE exact match、per-repo results |
| Cost | token、LLM calls、wall time、candidate count |

当前数据集没有唯一人工 BIC，candidate/Judge 层需要人工标注 case-study 子集，不能用 affected-version exact match 冒充 BIC accuracy。

## 10. 论文 Case Study 的推荐组织

建议选择 6 个主 case 和 2 个 positive controls：

| 研究问题 | Case | 证明内容 |
|---|---|---|
| RQ-CS1: 为什么普通 blame 即使找到相关提交仍会失败？ | CVE-2020-27814、CVE-2020-15466 | fix-series 假 BIC；manifestation line 不等于 introduction |
| RQ-CS2: 为什么 BIC 正确性与 affected-version 正确性不同？ | CVE-2020-11984 | canonical BIC 与 branch-local BIC 分离 |
| RQ-CS3: 为什么 patch-level root cause 不足？ | CVE-2020-11869、CVE-2020-14212 | 过宽因果推断；结构覆盖不等于语义覆盖 |
| RQ-CS4: 工程契约如何影响 Agent 可靠性？ | CVE-2022-0171、CVE-2020-19667 | schema/binding 失败级联 |
| Positive control: top-k 与 add-only 何时有效？ | CVE-2020-8231、CVE-2022-0286 | 多角色锚点；guard-to-use 反推 |

每个 case 应统一展示：

1. 修复语义与漏洞谓词；
2. baseline 选择的 anchor；
3. blame/搜索候选轨迹；
4. baseline 输出 BIC；
5. BIC 到 release 的转换结果；
6. 失败发生在哪一层；
7. 拟议模块如何改变候选或边界；
8. 对应 ablation 结果。

## 11. 当前可支持和不可支持的论文结论

### 可支持

- Agentic-SZZ 在候选历史清晰、BIC 位于正确 release lineage 的 case 上具有高精度；latest-FIC Micro-P 为 99.66%，13/30 个 CVE 完全正确。但其总体覆盖率较低，主要表现为 Recall 下降和空结果。
- MAS-SZZ 的语义根因和 pre-fix statement 阶段显著提高了覆盖率、召回率和 add-only 性能；latest-FIC Micro-F1 为 85.31%，add-only topology mean F1 为 94.3%。但错误锚点、trace 截断和 branch mismatch 仍会造成严重边界误差。
- Root Cause Agent 对已接受 case 的根因正确率为 75%，anchor hunk precision 为 87.5%，并提供可审计的谓词、锚点和证据结构；其不足集中在 evidence-link 精确性、最小性和 schema 鲁棒性。
- 三种方法存在可验证的阶段互补：VulnGraph 适合证据契约，MAS-SZZ 适合语义 anchor recall，Agentic-SZZ 适合结构化历史候选扩展。
- Add-only 需要从新增修复谓词反推父版本旧 use/invariant，而不是机械 blame 新增行附近上下文。
- branch-aware conversion 是 affected-version 任务的独立必要模块。

### 暂不可支持

- 当前 10-CVE Root Cause baseline 尚未运行 Judge/BIC/版本转换，不能宣称其最终性能优于 Agentic-SZZ 或 MAS-SZZ。
- 30-CVE 是 pilot，不足以支撑统计显著性的 SOTA 结论。
- 数据集没有唯一 BIC 真值，不能把高 affected-version F1 等同于高 BIC accuracy。
- Linux 仓库当前 shallow，相关 case 不能作为最终正式结果。

## 12. 核心判断

当前最值得深挖的不是“哪个 Agent 更聪明”，而是四个可验证的研究 gap：

1. **Patch-to-root-cause gap**：修复动作不等于漏洞因果机制。
2. **Root-cause-to-anchor gap**：正确根因文本不等于正确历史追踪语句。
3. **Anchor-to-BIC gap**：last-touch commit 不等于首次形成漏洞的提交。
4. **BIC-to-version gap**：canonical BIC 不等于每个 release branch 的受影响边界。

拟议系统若能分别建立证据契约、top-k semantic anchors、transition Judge 和 branch-aware adapter，创新点会比“用更强 LLM 替换 baseline”更清晰，也更容易通过分层实验和 case study 证明。

## 13. 本地证据索引

### 统一评估结果

- `VulnVersion/analysis/bic_baseline_30_analysis.md`
- `VulnVersion/analysis/bic_baseline_30_topology_only.json`
- `VulnVersion/analysis/bic_baseline_30_union.json`

### VulnGraph Root Cause baseline

- `VulnGraph/runs/batches/root-cause-v2-semantic-baseline-10/manual_metrics_summary.json`
- `VulnGraph/runs/batches/root-cause-v2-semantic-baseline-10/manual_semantic_review.md`
- `VulnGraph/runs/batches/root-cause-v2-semantic-baseline-10/failure_taxonomy.json`
- 各 CVE 子目录中的 `raw_response.txt`、`parsed_output.json`、`contract_lint.json`、`parse_error.json` 和 `evidence_trace.json`

### Agentic-SZZ 代码与输出

- `Replication/BaseLine(Vulnerability-affected versions identification How far are we)/ComparisonMethod/AgenticSZZ-main/AgenticSZZ-main/agentic_szz/szz/blame.py:123`
- `Replication/BaseLine(Vulnerability-affected versions identification How far are we)/ComparisonMethod/AgenticSZZ-main/AgenticSZZ-main/agentic_szz/agent/graphiti_tools.py:298`
- `Replication/BaseLine(Vulnerability-affected versions identification How far are we)/ComparisonMethod/AgenticSZZ-main/AgenticSZZ-main/agentic_szz/agent/bic_search_agent.py:532`
- `Replication/BaseLine(Vulnerability-affected versions identification How far are we)/ComparisonMethod/AgenticSZZ-main/AgenticSZZ-main/results/eval/BaseDataSet30_full_20260611_085254.json`

### MAS-SZZ 代码与输出

- `Replication/BaseLine(Vulnerability-affected versions identification How far are we)/ComparisonMethod/MAS-SZZ-main/MAS-SZZ-main/agents/bic_agent.py:114`
- `Replication/BaseLine(Vulnerability-affected versions identification How far are we)/ComparisonMethod/MAS-SZZ-main/MAS-SZZ-main/agents/root_cause_reviewer.py:25`
- `Replication/BaseLine(Vulnerability-affected versions identification How far are we)/ComparisonMethod/MAS-SZZ-main/MAS-SZZ-main/pipeline.py:249`
- `Replication/BaseLine(Vulnerability-affected versions identification How far are we)/ComparisonMethod/MAS-SZZ-main/MAS-SZZ-main/result/save_logs_B30/`
