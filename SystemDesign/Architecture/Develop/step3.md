# VulnVersion Step3 开发设计文档

更新时间：2026-05-13

本文档是 VulnVersion Step3 的当前维护版设计文档。旧版中大量已经被否定的方案、历史调参过程和冗余实现说明已经删除。后续 Step3 开发以本文档为主。

## 1. Step3 当前目标

Step3 的目标不是做 commit blame，也不是恢复每条 release line 上的 FIC/VIC commit。

Step3 的目标是：

> 给定一个 CVE、目标 repo、fix commit family，以及 Step1/Step2 产生的漏洞语义证据，识别该 CVE 影响的全部 release tags。

当前有效主线是：

```text
release tags
-> release filter / version normalization
-> repo-aware VersionTree / line-family graph
-> fix commit reachability evidence
-> active-line scheduler
-> ASBS / sentinel probes on selected lines
-> agent judge selected probe tags
-> interval inference
-> affected versions
```

当前正在攻克的问题是：

> 当前 scheduler 仍然激活了太多无关 release lines，导致真实 OpenCode agent probe 成本过高。

## 2. 不可变原则

1. 正式数据集统一使用 `E:\AI\Agent\workflow\VulnVersion\DataSet\BaseDataOrder.json`。
2. 任何新的 Step3 tag-plan 策略必须先在 1128 CVE 上做 simulator，不能直接进入主流程。
3. GT 只允许用于 simulator 和 final evaluation，不能进入真实 Step3 planning，也不能进入 agent prompt。
4. agent 只做 selected tag 的 `AFFECTED / NOT_AFFECTED` 判别，不负责规划 tag plan。
5. 不恢复 BAPEE / line-local FIC recovery 作为主线。当前数据不支持把它们作为冲击 90%+ 指标的主路径。它们最多作为历史负结果或离线研究材料，不再作为后续 Step3 优化主线。
6. 不使用 `git tag --contains <fix>` 做 hard deletion；它只能作为 evidence / priority hint。
7. 不用固定 probe budget、max_tags、hard cutoff 解决成本问题。必须从 line activation 和 evidence quality 上降本。
8. `CERT_ABSENT` / `CERT_FIXED` 只有在全量 simulator 证明足够安全后才能进入主路径；普通 touched files / 普通 tokens 不能作为 hard certificate。
9. 证据优先：所有 Step3 方法设计必须先有源码、数据集、git 命令或实验脚本支撑。没有自底向上实验结果的自顶向下方案，只能标记为 hypothesis，不能进入主路径。
10. 目标是 affected versions，不是 commit blame：Step3 的输出是 affected release tags / affected intervals。SZZ、VIC commit、fix commit 只能作为 evidence 或加速信息，不能取代 version-space 判定。
11. 不允许用截断伪装效率：默认算法不能依赖 `max_tags`、`unknown_mode`、`cross_line_early_stop` 这类旧策略控制成本。成本应由 line-local probing 和 interval inference 控制。

## 3. 当前源码状态

当前 Step3 已经不是旧的 tag-plan full scan。

主要模块：

| 模块 | 作用 | 当前状态 |
| --- | --- | --- |
| `vulnversion/stage3_verify/version_registry.py` | release tag 过滤、版本规范化、line key 解析 | 保留，仍是 VersionTree 基础 |
| `vulnversion/stage3_verify/vuln_tree.py` | 构建 repo-aware line/family graph 和 runtime skeleton | 保留，但不再把 line-local FIC recovery 作为主线 |
| `vulnversion/stage3_verify/git_reachability.py` | batch 计算 fix commits 被哪些 tags 包含 | 保留，作为 fix reachability evidence |
| `vulnversion/stage3_verify/line_scheduler.py` | 当前 staged active-line scheduler | 已接入，但仍需优化无关 line 激活 |
| `vulnversion/stage3_verify/asbs_line.py` | line 内 ASBS / sentinel probe 逻辑 | 已接入 |
| `vulnversion/stage3_verify/artifact_eval.py` | official / ablation evaluation buckets | 已接入 |
| `vulnversion/stage3_verify/verify_tags.py` | Step3 主流程入口，保留 explicit tags 模式 | 已接入当前主流程，但下一轮需要替换 scheduler 策略前先做 simulator |

必须保留的兼容路径：

- explicit tags 模式：调用方显式传入 tags 时，Step3 逐个交给 agent judge，不走 scheduler。
- artifact 输出：`tag_plan.json`、`vuln_tree.json`、`vuln_tree_runtime.json`、`scheduler_plan.json`、`line_intervals.json`、`per_tag_verdict.jsonl`、`per_tag_verdict.csv`、`eval.json`。

已经剔除为主线的旧方案：

- legacy `max_tags`
- `unknown_mode`
- `older_line_window`
- cross-line early stop
- legacy `BISECT_INFER`
- line-local FIC recovery
- BAPEE
- RCI token prefilter hard decision
- anchor relocation 作为 tag-plan 依据

## 4. 当前 VersionTree / line 建模结论

Step3 仍然需要建 line/family graph。全局单线 ASBS 不可靠，因为真实 affected tags 在全局版本顺序上经常出现 `A-N-A` 形态，不能二分。

当前使用 repo-aware line/family graph，而不是照搬 generic TDSC 规则。

已确认的 repo-level 结论：

| repo | 当前 line 策略 | 原因 |
| --- | --- | --- |
| `curl` | 保持单线 | generic TDSC 会拆成大量 line，probe 暴涨 |
| `ImageMagick` | 保持 `7.0 / 7.1` 主线 | hybrid 拆分会显著增加 probe |
| `openssl` | 使用 `current_plus_merge_mainline_09` 候选 | 比 generic TDSC 更稳，避免 fips/engine/mainline 混合 |
| `FFmpeg / qemu / wireshark / linux` | 保留 repo-aware family graph | 降本重点不在重建 line，而在减少 active probes |
| `httpd / openjpeg` | 保留当前 repo-aware line | 当前成本较低，优先级低于高 probe repo |

论文表述边界：

- 可以把 VersionTree 作为 Step3 的核心图结构之一。
- 不能声称某个通用 line parsing 规则适用于所有 repo。
- 应表述为“repo-aware version tree construction”，并报告不同 repo 的 tag naming convention 差异。

## 5. 当前 ASBS / sentinel 规则

当前 line 内 probe 规则：

| 情况 | 规则 |
| --- | --- |
| `N...A` | 二分找 first affected |
| `A...N` | 二分找 last affected |
| `N...N` | 内部均匀 sentinel，当前 `NN_SENTINEL_COUNT=3` |
| `A...A` | 中点 sentinel，当前 `AA_SENTINEL_COUNT=1` |
| fixed-containing segment | endpoint + 1 个中点，当前 `FIXED_SEG_SENTINEL=1` |
| `A...A` 冲突 | fallback full scan，有最大扫描保护阈值 |

重要结论：

- 单纯增加 sentinel 数量不是当前主瓶颈。
- 目前 FN 主要来自 active line 内稀疏 / singleton affected tag 没被 ASBS 捕获，以及极少数 skipped affected line。
- 后续不能通过扩大 sentinel 或固定 probe budget 来解决成本问题。

## 6. 当前候选主方案

当前待选主方案：

```text
transition_scout_s4_expand2_allfixfile_s4
```

含义：

1. 从 fix reachability transition line 附近启动。
2. 对 no-fix lines 做 stride-4 scout。
3. affected positive line 沿 same-family 邻居扩展。
4. 对 all-fix but touched-file endpoint lines 做补充 scout。
5. line 内仍使用 ASBS / sentinel。

当前定位：

- 这是当前低成本高召回候选主方案。
- 它还没有成为最终方案。
- 它暴露出的主要问题是无关 line 激活仍然过多。

## 7. Scheduler failure corpus

目的：

- 固定分析 `transition_scout_s4_expand2_allfixfile_s4`。
- 把 FN、FP、skipped affected line、active-line ASBS miss、无关 line 激活来源拆开。
- 为下一轮 dynamic line activation scheduler 提供数据依据。

脚本：

```text
E:\AI\Agent\workflow\VulnVersion\tests\build_scheduler_failure_corpus.py
```

运行命令：

```powershell
cd E:\AI\Agent\workflow\VulnVersion
python tests\build_scheduler_failure_corpus.py --dataset DataSet\BaseDataOrder.json --repo-root repo --out tests\scheduler_failure_corpus
```

输出目录：

```text
E:\AI\Agent\workflow\VulnVersion\tests\scheduler_failure_corpus\
```

输出文件：

| 文件 | 内容 |
| --- | --- |
| `summary.json` | 总体指标、repo 指标、version-level 指标 |
| `irrelevant_activation_by_reason.json` | 无关 active line 的来源拆解 |
| `fn_cases.json` | FN CVE 级别 dump |
| `fp_cases.json` | FP CVE 级别 dump |
| `skipped_affected_lines.json` | 被 scheduler 跳过的 affected lines |
| `per_cve_line_runtime.jsonl` | 每个 CVE 的 line runtime 状态 |
| `report.md` | 简短报告 |

### 7.1 总体结果

数据集：`BaseDataOrder.json`，1128 CVE。

| metric | value |
| --- | ---: |
| avg probes/CVE | 45.05 |
| p50 probes | 39 |
| p95 probes | 92 |
| exact CVEs | 1115/1128 |
| FN CVEs | 9 |
| FP CVEs | 4 |
| version TP | 59124 |
| version FP | 12 |
| version FN | 10 |
| version TN | 151120 |
| precision | 0.999797 |
| recall | 0.999831 |
| F1 | 0.999814 |
| avg active lines/CVE | 33.01 |
| avg affected lines/CVE | 17.21 |
| avg irrelevant active lines/CVE | 15.80 |
| irrelevant active line ratio | 47.88% |

解释：

- 当前方案已经比旧方案大幅降低 probe。
- 但平均每个 CVE 仍激活 `33.01` 条 line，其中 `15.80` 条是无关 line。
- 主要成本瓶颈已经收敛为 line relevance selection。

### 7.2 FN 来源

| FN source | version tags |
| --- | ---: |
| `active_line_missed_asbs_or_sparse` | 9 |
| `skipped_affected_line` | 1 |

解释：

- skipped affected line 不是主要 FN 来源，目前只有 1 个 tag。
- 主要 FN 来自 line 已经被激活，但 ASBS / sentinel 没命中稀疏或 singleton affected tag。
- 唯一 skipped affected line case：

```text
repo = wireshark
CVE = CVE-2022-0586
line = 0.99
tag = wireshark-0.99.8
```

### 7.3 无关 active line 来源

按 primary activation reason：

| reason | irrelevant active lines |
| --- | ---: |
| `scout_stride` | 9467 |
| `all_fix_file_scout` | 3779 |
| `positive_neighbor` | 3087 |
| `nohit_fallback` | 1316 |
| `fix_transition_neighbor` | 179 |

按 any activation reason：

| reason | irrelevant activations |
| --- | ---: |
| `scout_stride` | 9467 |
| `all_fix_file_scout` | 3779 |
| `positive_neighbor` | 3617 |
| `nohit_fallback` | 1817 |
| `fix_transition_neighbor` | 179 |

结论：

- 最大浪费不是 fix transition seed。
- 最大浪费来自固定 stride scout 和 all-fix-file scout。
- positive neighbor 也有明显浪费，但不能简单删除，因为它是当前保证 recall 的核心扩展机制之一。
- fix_transition_neighbor 不是主要噪声来源。

### 7.4 repo-level 浪费来源

| repo | dominant irrelevant sources |
| --- | --- |
| `linux` | `scout_stride=8113`, `all_fix_file_scout=3250`, `positive_neighbor=2339` |
| `qemu` | `scout_stride=457`, `all_fix_file_scout=225`, `positive_neighbor=190` |
| `FFmpeg` | `scout_stride=319`, `positive_neighbor=206`, `all_fix_file_scout=199` |
| `wireshark` | `scout_stride=232`, `positive_neighbor=147`, `all_fix_file_scout=101` |
| `openssl` | `scout_stride=272`, `positive_neighbor=145`, `fix_transition_neighbor=65` |
| `httpd` | `scout_stride=48`, `positive_neighbor=29`, `nohit_fallback=20` |
| `openjpeg` | `positive_neighbor=31`, `scout_stride=26` |
| `ImageMagick` | `fix_transition_neighbor=57` |
| `curl` | no irrelevant active line |

解释：

- `linux` 是最大成本来源，应优先优化 `scout_stride` 与 `all_fix_file_scout`。
- `qemu / FFmpeg / wireshark / openssl` 同样需要 evidence-ranked activation。
- `curl` 不应复杂化；它当前无无关 active line。

## 8. 当前问题收敛

当前不再主要讨论：

- 是否需要 line：需要。
- 是否需要 fix reachability：需要，但只能做 evidence。
- 是否需要 ASBS：需要，但 ASBS 不是成本瓶颈本身。
- 是否增加 sentinel：暂不应作为主优化方向。
- 是否恢复 line-local FIC recovery：不恢复。

当前真正问题：

> 怎样让 scheduler 少激活无关 line，同时不漏掉 affected line。

拆成两个子问题：

1. line activation scheduler 太粗：`scout_stride`、`all_fix_file_scout`、`positive_neighbor` 引入大量无关 line。
2. VET evidence quality 不够：当前 Step2 还不能稳定给出 root-cause-level 的 file/function/token/guard 证据，因此不能安全地 hard prune。

## 9. 长期有效的实测结论

本节只记录已经由本地脚本、1128 CVE 数据集或真实小样本支撑的结论。后续修改 Step3 时，优先遵守这些约束。

### 9.1 数据集和 GT 映射

来源：

- `tests/affected_version_monotonicity_sorted/summary.json`
- `tests/gt_mapping_stability/summary.json`

结论：

| 结论 | 数据 |
| --- | ---: |
| 总 CVE 数 | 1128 |
| 所有 affected lines 都连续的 CVE | 1121 |
| 存在非连续 affected line 的 CVE | 7 |
| 输入 affected_version 顺序单调的 CVE | 1077 |
| 输入 affected_version 顺序非单调的 CVE | 51 |
| release tag 完全映射成功的 CVE | 1124 |
| 存在未映射 tag 的 CVE | 4 |
| 非空 affected_version 的 GT mapping stability | 1097/1097 |
| affected_version 为空未进入 mapping gate 的 CVE | 31 |

长期约束：

- line 内 affected interval 高度连续，所以 line-local interval inference 是合理主线。
- 仍有 7 个 CVE 存在非连续 line，不能把 interval inference 写成绝对定理。
- `BaseDataOrder.json` 的 affected_version 需要按 release/version 语义处理，不能依赖输入顺序。

### 9.2 Sentinel 不能单独解决成本问题

来源：

- `tests/step3_gt_simulator_order_v2/summary.json`

`all_lines` 全量 line 策略下，N...N sentinel 数量的效果：

| sentinel | avg probes | p95 probes | exact CVEs | FN CVEs | micro recall | micro F1 |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 0 | 70.98 | 109 | 1021 | 98 | 0.912166 | 0.953947 |
| 1 | 77.34 | 137 | 1062 | 58 | 0.978236 | 0.988888 |
| 2 | 82.51 | 152 | 1072 | 49 | 0.986979 | 0.993379 |
| 3 | 87.20 | 172 | 1083 | 39 | 0.994656 | 0.997270 |

长期约束：

- `NN_SENTINEL_COUNT=3` 是高召回配置，但它本身成本较高。
- 单纯继续增加 sentinel 没有解决 line activation 浪费。
- 后续优化重点应在 selected lines，而不是在所有 line 上继续加 probe。

### 9.3 Git-guided soft evidence 有效，但不能 hard delete

来源：

- `tests/git_guided_simulator_order_v2/summary.json`
- `tests/staged_expansion_simulator_order_v2/summary.json`
- `tests/module_backed_step3_simulator/summary.json`

关键结果：

| 策略 | avg probes | p95 probes | exact CVEs | FN CVEs | micro F1 |
| --- | ---: | ---: | ---: | ---: | ---: |
| `all_lines_asbs s=3` | 87.20 | 172 | 1083 | 39 | 0.997270 |
| `git_guided_soft s=3 fs=0` | 84.15 | 155 | 1113 | 9 | 0.999865 |
| `git_guided_soft s=3 fs=1` | 85.55 | 162 | 1114 | 8 | 0.999882 |
| `staged_nofix_stride3_file` reference | 70.53 | 130 | 1114 | 8 | 0.999882 |
| module-backed `staged_nofix_stride3_file` | 68.34 | 122 | 1112 | 8 | 0.999822 |

长期约束：

- fix reachability 是强 evidence，可以指导调度顺序。
- fix reachability 不能作为 hard deletion；早期 hard filter 实验已经证明会漏报。
- module-backed simulator 比早期复制逻辑 simulator 更接近源码实现，后续改源码前应优先对齐 module-backed 口径。

### 9.4 直接照搬 generic TDSC VersionTree 不适合 9 repo

来源：

- `tests/tdsc_version_tree_builder_simulator/summary.json`
- `tests/openssl_line_strategy_candidate_comparison/summary.json`

全量 1128 CVE 结果：

| builder | avg probes | p95 probes | exact CVEs | version FN | F1 |
| --- | ---: | ---: | ---: | ---: | ---: |
| `current_version_registry` | 68.36 | 123 | 1112 | 9 | 0.999822 |
| `tdsc_hybrid_repo_aware` | 70.43 | 123 | 1112 | 9 | 0.999822 |
| `tdsc_version_tree` | 76.02 | 139 | 1112 | 9 | 0.999822 |

OpenSSL 专项对比：

| variant | avg probes | p95 probes | exact CVEs | version FN | F1 |
| --- | ---: | ---: | ---: | ---: | ---: |
| `major_minor_family_partition` | 62.46 | 70 | 48/50 | 1 | 0.998331 |
| `current_plus_merge_mainline_09` | 69.50 | 79 | 48/50 | 1 | 0.998331 |

长期约束：

- VersionTree 必须 repo-aware，不能机械照搬 TDSC 的 Linux-oriented 版本线规则。
- `curl` 保持单线；`ImageMagick` 保持 `7.0/7.1`；OpenSSL 需要单独处理 family/line partition。
- OpenSSL 的 `major_minor_family_partition` 成本更低，但仍需 case review 后才能替换默认策略。

### 9.5 低成本 scheduler 的主要 trade-off

来源：

- `tests/global_state_line_scheduler_simulator_v4/summary.json`
- `tests/step3_low_cost_scheduler_simulator/summary.json`

关键结果：

| 策略 | avg probes | p95 probes | exact CVEs | version FN | F1 | 结论 |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `control_current` | 68.06 | 123 | 1116 | 9 | 0.999822 | 高召回但无关 line 多 |
| `global_scout_s4_all` | 64.88 | 118 | 1116 | 9 | 0.999822 | 小幅降本，收益有限 |
| `transition_first_no_fallback` | 5.51 | 29 | 268 | 31636 | 0.634779 | 证明只看 fix transition 会严重漏报 |
| `transition_scout_s4_all_expand2` | 41.17 | 84 | 1112 | 38 | 0.999577 | 性价比高但 FN 增加 |
| `transition_scout_s4_expand2_allfixfile_s4` | 45.06 | 92 | 1115 | 10 | 0.999814 | 当前待选主方案 |
| `tdsc_boundary_first` | 43.86 | 91 | 1102 | 229 | 0.997959 | 降本明显但 version FN 明显增加 |

长期约束：

- transition-first 只能作为 seed，不能作为唯一搜索范围。
- 当前最有用的候选是 `transition_scout_s4_expand2_allfixfile_s4`。
- 如果继续降本，必须减少无关 line activation，而不是砍掉 fallback。

### 9.6 现有 cheap VET evidence 不足以做 hard pruning

来源：

- `tests/step3_vet_evidence_dynamic_scheduler/summary.json`
- `tests/vet_line_relevance_scheduler/summary.json`

关键结果：

| 策略 | avg probes | exact CVEs | FN CVEs | version FN | F1 | 结论 |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `base_allfixfile_s4` | 45.06 | 1115 | 9 | 10 | 0.999814 | 当前基线 |
| `vet_ranked_scout_only` | 36.75 | 1110 | 14 | 50 | 0.999476 | 降本但 FN 增加 |
| `vet_neighbor_t0.20` | 43.01 | 993 | 131 | 1680 | 0.985489 | 不能用当前 VET gate neighbor |
| `vet_current_seed_cert_absent` | 49.93 | 938 | 186 | 3342 | 0.970811 | 当前 CERT_ABSENT 不安全 |
| `vet_cert_fixed_h0.60_m0.30_s6` | 46.35 | 938 | 186 | 3342 | 0.970811 | 当前 CERT_FIXED 不安全 |

长期约束：

- 当前 Step2/VET evidence 只能用于 priority / prompt context，不能做 hard certificate。
- `CERT_ABSENT` / `CERT_FIXED` 必须等待 root-cause-level VET 和 admission simulator 通过。
- 不能用 touched files、普通 tokens、粗粒度 score 删除 line。

### 9.7 Failure corpus 指出当前真正瓶颈

来源：

- `tests/scheduler_failure_corpus/summary.json`
- `tests/scheduler_failure_corpus/irrelevant_activation_by_reason.json`
- `tests/scheduler_failure_corpus/fn_cases.json`
- `tests/scheduler_failure_corpus/skipped_affected_lines.json`

当前待选主方案 `transition_scout_s4_expand2_allfixfile_s4`：

| metric | value |
| --- | ---: |
| avg probes | 45.05 |
| p95 probes | 92 |
| exact CVEs | 1115/1128 |
| version FN | 10 |
| version FP | 12 |
| F1 | 0.999814 |
| avg active lines | 33.01 |
| avg irrelevant active lines | 15.80 |
| irrelevant active line ratio | 47.88% |

FN 来源：

| source | version tags |
| --- | ---: |
| `active_line_missed_asbs_or_sparse` | 9 |
| `skipped_affected_line` | 1 |

无关 active line primary reason：

| reason | irrelevant active lines |
| --- | ---: |
| `scout_stride` | 9467 |
| `all_fix_file_scout` | 3779 |
| `positive_neighbor` | 3087 |
| `nohit_fallback` | 1316 |
| `fix_transition_neighbor` | 179 |

长期约束：

- 当前最大浪费来自 `scout_stride` 和 `all_fix_file_scout`，其次是 `positive_neighbor`。
- skipped affected line 不是主要 FN 来源；主要 FN 已转移到 active line 内稀疏 / singleton affected tag。
- 下一轮应做 evidence-ranked scout queue、late all-fix-file scout、family interval closure，而不是继续扩大固定 stride。

## 10. 下一步必须执行的开发顺序

### P0：已经完成

1. 构建 `scheduler_failure_corpus`。
2. 拆解 `transition_scout_s4_expand2_allfixfile_s4` 的 FN / FP / irrelevant activation。
3. 将结果写入本文档。

### P1：已完成 `simulate_dynamic_line_activation_scheduler.py`

目标：

> 测试 family interval closure + evidence-ranked queue 是否能减少无关 active line。

必须遵守：

- 不做 hard deletion。
- 不把 low-risk line 从 VulnTree 删除。
- 只改变 line/tag 的 runtime state、priority、activation order。
- GT 只用于 simulator oracle。
- 任何 evidence 只能影响 priority，不能直接输出 `NOT_AFFECTED`。

建议路径：

```text
E:\AI\Agent\workflow\VulnVersion\tests\simulate_dynamic_line_activation_scheduler.py
```

输出目录：

```text
E:\AI\Agent\workflow\VulnVersion\tests\dynamic_line_activation_scheduler\
```

必须输出：

| 文件 | 内容 |
| --- | --- |
| `summary.json` | 策略总表 |
| `per_strategy.json` | 每个策略指标 |
| `per_cve.jsonl` | 每个 CVE 的 line activation 轨迹 |
| `fn_cases.json` | 新策略 FN dump |
| `irrelevant_activation_by_reason.json` | 新策略无关激活来源 |
| `line_queue_events.jsonl` | line runtime queue 事件 |
| `report.md` | 结论报告 |

必须比较的策略：

| strategy | 说明 |
| --- | --- |
| `control_transition_scout_s4_expand2_allfixfile_s4` | 当前候选主方案，作为对照 |
| `family_interval_closure_only` | 只测试 family 内 interval closure，不引入 VET evidence |
| `evidence_ranked_scout_queue` | scout candidates 按 VET evidence score 排序，不 hard delete |
| `late_all_fix_file_scout` | all-fix-file scout 延迟到边界未闭合或 high-risk evidence 时执行 |
| `ranked_positive_neighbor` | positive neighbor 先入队，不立即执行；按 evidence 和 family gap 排序 |
| `hybrid_dynamic_scheduler` | 组合上述安全部分 |

必须统计：

- avg probes/CVE
- p50 / p95 probes
- exact CVEs
- FN CVEs
- FP CVEs
- version TP/FP/FN/TN
- precision / recall / F1
- avg active lines
- avg irrelevant active lines
- irrelevant active line ratio
- skipped affected lines
- active-line ASBS miss
- per-repo dominant waste source

验收标准：

- 相比 control，avg probes 必须明显下降。
- version FN 不能显著增加。
- 如果 FN 增加，必须给出 case-level 根因。
- 如果没有策略优于 control，也必须如实报告。

#### P1.1 实测命令

```powershell
cd E:\AI\Agent\workflow\VulnVersion
python tests\simulate_dynamic_line_activation_scheduler.py --dataset DataSet\BaseDataOrder.json --repo-root repo --out tests\dynamic_line_activation_scheduler
```

运行结果：

- 数据集：`BaseDataOrder.json`
- CVE 数：1128
- failures：0
- 输出目录：`E:\AI\Agent\workflow\VulnVersion\tests\dynamic_line_activation_scheduler\`

输出文件：

| 文件 | 状态 |
| --- | --- |
| `summary.json` | 已生成 |
| `per_strategy.json` | 已生成 |
| `per_cve.jsonl` | 已生成 |
| `fn_cases.json` | 已生成 |
| `irrelevant_activation_by_reason.json` | 已生成 |
| `line_queue_events.jsonl` | 已生成 |
| `report.md` | 已生成 |

#### P1.2 策略对比结果

| strategy | avg probes | p50 | p95 | exact CVEs | FN CVEs | FP CVEs | version TP | version FP | version FN | version TN | precision | recall | F1 | avg active lines | avg irrelevant lines | irrelevant ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `control_transition_scout_s4_expand2_allfixfile_s4` | 45.06 | 39 | 92 | 1115/1128 | 9 | 4 | 59124 | 12 | 10 | 151120 | 0.999797 | 0.999831 | 0.999814 | 33.02 | 15.82 | 47.90% |
| `family_interval_closure_only` | 42.88 | 37 | 87 | 1106/1128 | 18 | 4 | 58926 | 12 | 208 | 151120 | 0.999796 | 0.996483 | 0.998137 | 31.80 | 14.61 | 45.93% |
| `evidence_ranked_scout_queue` | 36.75 | 26 | 82 | 1110/1128 | 14 | 4 | 59084 | 12 | 50 | 151120 | 0.999797 | 0.999154 | 0.999476 | 26.19 | 9.01 | 34.41% |
| `late_all_fix_file_scout` | 42.42 | 37 | 86 | 1112/1128 | 12 | 4 | 59096 | 12 | 38 | 151120 | 0.999797 | 0.999357 | 0.999577 | 30.81 | 13.63 | 44.24% |
| `ranked_positive_neighbor` | 43.01 | 38 | 84 | 993/1128 | 131 | 4 | 57454 | 12 | 1680 | 151120 | 0.999791 | 0.971590 | 0.985489 | 31.68 | 15.37 | 48.51% |
| `hybrid_dynamic_scheduler` | 32.96 | 23 | 75 | 1010/1128 | 114 | 4 | 56826 | 12 | 2308 | 151120 | 0.999789 | 0.960970 | 0.979995 | 23.96 | 7.69 | 32.07% |

#### P1.3 相对 control 的变化

| strategy | avg probe delta | exact CVE delta | irrelevant active line delta | version FN delta | 判断 |
| --- | ---: | ---: | ---: | ---: | --- |
| `evidence_ranked_scout_queue` | -8.31 | -5 | -6.81 | +40 | 降本明显，但 FN 增加，不可直接接入 |
| `family_interval_closure_only` | -2.19 | -9 | -1.21 | +198 | 降本有限，FN 增加明显，不可接入 |
| `late_all_fix_file_scout` | -2.64 | -3 | -2.19 | +28 | 当前最稳的降本候选，但仍不满足高召回目标 |
| `ranked_positive_neighbor` | -2.05 | -122 | -0.45 | +1670 | 不安全 |
| `hybrid_dynamic_scheduler` | -12.10 | -105 | -8.13 | +2298 | 不安全 |

#### P1.4 结论

本轮没有任何动态策略可以直接替代 control。

关键原因：

- `evidence_ranked_scout_queue` 可以把 avg probes 从 `45.06` 降到 `36.75`，也能把无关 active line ratio 从 `47.90%` 降到 `34.41%`，但 version FN 从 `10` 增加到 `50`。
- `late_all_fix_file_scout` 是当前最接近可用的降本候选，但 version FN 仍从 `10` 增加到 `38`。
- `ranked_positive_neighbor` 和 `hybrid_dynamic_scheduler` 证明当前 evidence score 不能安全地延迟 positive neighbor；它们会跳过大量 affected line。
- family interval closure 本身不能解决问题，反而会在若干 repo 上错误关闭 family 搜索空间。

因此：

1. 当前 cheap VET evidence 已经能帮助排序，但不够支撑安全 deferral。
2. line activation 的继续降本必须先提升 Step2 root-cause-level VET 质量。
3. 在 VET 质量没有提升前，`control_transition_scout_s4_expand2_allfixfile_s4` 仍是更安全的候选主方案。
4. 下一轮不应继续调阈值硬压 probe，而应先建设 VET evidence admission simulator。

### P2：强化 Step2 root-cause-level VET

目标：

> 提升 Step3 agent judge 和 line relevance scoring 的证据质量。

必须先做 deterministic diff extractor，再让 agent 补语义。

建议新增或强化：

```text
vulnversion/stage2_rci_navigation/vet_schema.py
vulnversion/stage2_rci_navigation/diff_extractor.py
vulnversion/stage2_rci_navigation/induce_rci.py
```

VET 不应只包含 touched files / 普通 tokens。至少应区分：

| 字段 | 说明 |
| --- | --- |
| `root_cause_files` | 漏洞根因相关文件，不是全部 touched files |
| `root_cause_functions` | 根因函数或近似局部作用域 |
| `vulnerable_sequences` | 删除/修改的关键 vulnerable sequence |
| `fix_guards` | 新增 guard/check/API call |
| `security_invariant` | 漏洞存在需要满足的语义条件 |
| `fix_effect` | patch 如何阻断漏洞机制 |
| `negative_evidence` | 哪些证据出现时可降低 affected 可能性 |
| `confidence` | 每项证据的来源与置信度 |

deterministic diff extractor 应先提供：

- changed files
- added / deleted hunks
- changed function scope
- deleted/modified short tokens
- added guard/check/API calls
- candidate vulnerable sequences
- candidate fixed sequences

agent 只在此基础上补：

- root cause summary
- vulnerability mechanism
- semantic invariant
- which tokens are root-cause-level rather than incidental

### P3：写 `simulate_vet_quality_admission.py`

目标：

> 评估 VET evidence 是否足够安全地进入 scheduler。

路径：

```text
E:\AI\Agent\workflow\VulnVersion\tests\simulate_vet_quality_admission.py
```

输出目录：

```text
E:\AI\Agent\workflow\VulnVersion\tests\vet_quality_admission\
```

必须评估：

| evidence | 用途 | 是否允许 hard decision |
| --- | --- | --- |
| root-cause file exists | priority | 默认不允许 |
| root-cause function exists | priority | 默认不允许 |
| vulnerable sequence exists | priority / conflict | 未验证前不允许 |
| fix guard exists | priority / fixed-side evidence | 未验证前不允许 |
| vulnerable sequence absent | possible `CERT_ABSENT` | 需要 wrong-certificate case 很低 |
| fix guard present + vulnerable sequence absent | possible `CERT_FIXED` | 需要 wrong-certificate case 很低 |

必须输出：

- evidence coverage
- wrong-certificate count
- wrong-certificate CVEs
- per-repo risk
- per-CVE evidence failure reason
- admission decision

进入主路径的条件：

- 只有 `CERT_ABSENT` / `CERT_FIXED` 的 wrong-certificate case 明显下降后，才能作为 hard certificate。
- 在此之前，VET evidence 只能影响 priority / activation order / prompt context。

### P4：18+ CVE 真实 OpenCode 小样本

只有 P1/P3 simulator 过关后，才做真实 agent 小样本。

要求：

- 9 repo 每个至少 2 个 CVE，总计不少于 18 个。
- 必须覆盖 high-probe repo：`FFmpeg / qemu / wireshark / linux / openssl`。
- 必须覆盖 low-probe repo：`curl / openjpeg / ImageMagick / httpd`。
- 必须覆盖 multi-commit CVE、single affected tag CVE、large affected interval CVE。

统计：

- actual probes
- wall-clock time
- per-probe latency
- agent_error / timeout
- precision / recall / F1
- CVE exact
- error cases

### P5：最后才改 `verify_tags.py` 主流程

只有满足以下条件才允许进入主流程修改：

1. `simulate_dynamic_line_activation_scheduler.py` 在 1128 CVE 上优于当前 control。
2. `simulate_vet_quality_admission.py` 证明 VET evidence 至少可安全做 priority。
3. 18+ CVE 真实 OpenCode 小样本没有出现不可接受的 agent error / latency / accuracy 问题。

主流程目标：

```text
build VulnTree
-> git_reachability
-> dynamic line activation scheduler
-> asbs_line
-> AgentRuntime.run_json
-> artifact_eval
```

## 11. 术语对照

| 英文术语 | 中文解释 |
| --- | --- |
| `fix transition seed` | fix commit 可达性变化点附近的初始种子 line |
| `sentinel` | 哨兵探测点，line 内选取的代表性 tag |
| `probe` | 一次 agent tag verdict 调用 |
| `scout_stride` | 固定步长侦察，例如每隔 4 条 line 激活一条 |
| `all_fix_file_scout` | 对包含修复相关文件的 line 做补充侦察 |
| `positive_neighbor` | 某 line 发现 affected 后，激活 same-family 邻居 |
| `irrelevant line` | 真实没有 affected tag 但被 scheduler 激活的 line |
| `evidence-ranked queue` | 基于 VET evidence 给候选 line 排序的队列 |
| `late scout` | 延迟执行某类 scout，只有边界未闭合或证据不足时才启动 |
| `sparse affected tag` | 某 line 上只有少量 affected tag |
| `singleton affected tag` | 某 line 上只有一个 affected tag |
| `guard` | 防漏报保护规则 |

## 12. 当前最终判断

当前 Step3 不能停留在 `transition_scout_s4_expand2_allfixfile_s4`。这个方案已经证明可显著降本，但 failure corpus 显示仍有 `47.88%` active lines 是无关 line。

`simulate_dynamic_line_activation_scheduler.py` 已经完成 1128 CVE 全量验证。结论是：当前 cheap evidence 可以减少 probe，但会显著增加 FN，不能直接接入主流程。

下一步应该做：

1. Step2 root-cause-level VET：先 deterministic diff extractor，再 agent 补语义。
2. `simulate_vet_quality_admission.py`：决定哪些 VET evidence 可以安全进入 scheduler。
3. 在 VET 质量提升后，重新运行 `simulate_dynamic_line_activation_scheduler.py`。
4. 18+ CVE 真实 OpenCode 小样本。
5. 最后才修改 `verify_tags.py` 默认主流程。

这是当前最符合数据证据的推进路线。
