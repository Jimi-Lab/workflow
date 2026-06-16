# VulnVersion Step3 当前架构骨干

最后更新：2026-05-01
项目路径：`E:\AI\Agent\workflow\VulnVersion`
Step3 目标：根据 `CVE + fix commit family` 识别该 CVE 影响的全部 release versions。
最终目标：在 1128 个 CVE、9 个目标 repo 上提升 F1、recall、CVE precision、version precision，并保持低开销、可解释、可复现。

本文档只保留当前有效设计。历史讨论中已经被数据否定或暂不采用的内容不再作为方法路线。后续任何 Step3 方案都必须同步更新本文档。

---

## 1. 不可变原则

1. **证据优先**：所有 Step3 方法设计必须先有源码、数据集、git 命令或实验脚本支撑。没有自底向上实验结果的自顶向下方案，只能标记为 hypothesis，不能进入主路径。
2. **目标是 affected versions，不是 commit blame**：Step3 的输出是 affected release tags / affected intervals。SZZ、VIC commit、fix commit 只能作为 evidence 或加速信息，不能取代 version-space 判定。
3. **agent 只做判别，不做规划**：agent 输入关键 tag 证据，输出 `AFFECTED / NOT_AFFECTED`。选择哪些 tags、如何推断 interval、如何计算 artifact，必须由 deterministic planner/verifier 完成。
4. **line 是核心建模单位**：不能把整个 repo 的 tags 简单拉平成一条全局序列做二分。全局序列中存在大量 `A-N-A`，不满足二分单调性。
5. **BAPEE / line-local FIC recovery 从 Step3 方法路线中剔除**：当前数据不支持把它们作为冲击 90%+ 指标的主路径。它们最多作为历史负结果或离线研究材料，不再作为后续 Step3 优化主线。
6. **不允许用截断伪装效率**：默认算法不能依赖 `max_tags`、`unknown_mode`、`cross_line_early_stop` 这类旧策略控制成本。成本应由 line-local probing 和 interval inference 控制。
7. **Agent backend 与 Step3 判定语义分离**：Step3 只依赖 `AgentRuntime` 协议调用 tag-level judge。当前可执行 backend 是 OpenCodeRuntime；Codex/Claude runtime 只预留，不改变 Step3 的 planner/judge 边界，也不自动复用 `.opencode/skills`。

---

## 2. 当前有效结论

Step3 当前应收敛为：

```text
repo git tags
  -> release tag filter
  -> version_registry line/family parsing
  -> build VulnTree
  -> per-line ASBS-first affected interval discovery
  -> union(all line affected intervals)
  -> artifacts + eval
```

核心判断：

- `VulnTree` 需要构建，因为 Step3 是 release-version graph 问题。
- `line` 需要构建，因为 affected versions 在 line 内高度连续，而全局序列不稳定。
- `BAPEE / line-local FIC recovery` 不再做，因为 fix commit 在大多数 affected lines 上不可见，恢复能力弱，且会把问题复杂化。
- `FIC/VIC commit` 不再是主路径依赖。若某个 fix commit 自然被某些 tag 包含，它只能作为 evidence / probe hint，不能作为每条 line 的规划前提。
- ASBS 的目标不是只找 first affected tag，而是为每条 line 找完整 affected interval。

---

## 3. 数据证据

### 3.1 line 内 affected interval 高度连续

实验：

- 数据集：`E:\AI\Agent\workflow\VulnVersion\DataSet\BaseDataSet.json`
- 脚本：`E:\AI\Agent\workflow\VulnVersion\tests\analyze_affected_version_monotonicity.py`
- 输出：`E:\AI\Agent\workflow\VulnVersion\tests\affected_version_monotonicity_sorted\summary.json`

结果：

- 总 CVE：`1128`
- 所有 line 都连续的 CVE：`1121`
- 存在非连续 line 的 CVE：`7`
- 所有 line 上输入顺序单调的 CVE：`1077`
- 存在未映射 tag 的 CVE：`4`
- affected line intervals 总数：`19408`
- full-line intervals：`18636`
- prefix-only intervals：`556`
- suffix-only intervals：`110`
- middle intervals：`98`
- non-contiguous intervals：`8`

结论：line-local interval discovery 是有数据支撑的。绝大多数 line 上 affected tags 是连续区间，适合用少量 probe + interval inference。

### 3.2 repo-level global ASBS 不可靠

实验：

- 脚本：`E:\AI\Agent\workflow\VulnVersion\tests\analyze_global_affected_runs.py`
- 输出：`E:\AI\Agent\workflow\VulnVersion\tests\global_affected_runs\summary.json`

结果：

- `semantic_global = family -> line -> version` 顺序下，`137/1128` 个 CVE 出现 `A ... N ... A`。
- `git tag --sort=-creatordate` 时间顺序下，`213/1128` 个 CVE 出现 `A ... N ... A`。
- repo-level 典型高风险：`FFmpeg 59/71`、`openssl 32/50`、`wireshark 32/50` 出现语义全局 `A-N-A`。

结论：把整个 repo 的 release tags 展平成一条全局线再二分，会破坏单调性。global ASBS 只能作为负面 baseline，不能作为 Step3 主路径。

### 3.3 global FIC baseline 会漏召回

实验：

- 脚本：`E:\AI\Agent\workflow\VulnVersion\tests\compare_global_fic_vs_vulntree.py`
- 输出：`E:\AI\Agent\workflow\VulnVersion\tests\global_fic_vs_vulntree\summary.json`
- 样本：9 repo，每 repo 随机 10 个 CVE，共 90 个 CVE。

结果：

- global candidate avg：`201.09`
- line-local candidate avg：`213.68`
- line-local probe avg：`43.08`
- global full GT coverage：`79/90`
- line-local candidate full GT coverage：`87/90`
- global avg GT coverage：`0.956`
- line-local candidate coverage：`0.998`
- FFmpeg：global full GT `3/10`，line-local `9/10`

结论：global FIC 看似简单，但存在明显 recall 损失。line-local 方法虽然建模更复杂，但实际 probe 数更低，coverage 更高。

### 3.4 line-local FIC recovery 不适合作为主线

实验：

- 脚本：`E:\AI\Agent\workflow\VulnVersion\tests\analyze_fix_containment_by_line.py`
- 输出：`E:\AI\Agent\workflow\VulnVersion\tests\fix_containment_by_line\*\summary.json`

非 Linux 主要结果：

| repo        | affected lines | with fix | without fix | no-fix rate |
| ----------- | -------------: | -------: | ----------: | ----------: |
| FFmpeg      |            872 |      165 |         707 |      0.8108 |
| ImageMagick |             87 |       71 |          16 |      0.1839 |
| curl        |             68 |       68 |           0 |           0 |
| httpd       |             84 |       12 |          72 |      0.8571 |
| openjpeg    |             75 |        0 |          75 |         1.0 |
| openssl     |            149 |       48 |         101 |      0.6779 |
| qemu        |            898 |        2 |         896 |      0.9978 |
| wireshark   |            510 |       26 |         484 |      0.9490 |

Linux 抽样 50 CVE：

- affected lines：`1484`
- with fix：`1`
- without fix：`1483`
- no-fix rate：`0.9993`

结论：大多数 affected lines 根本不包含 fix commit。继续围绕“把一个 fix commit 恢复/迁移到每条 line 的 FIC”会成为主要瓶颈，不适合作为 Step3 主方法。

### 3.5 BAPEE 负结果

历史实验：

- 输出：`E:\AI\Agent\workflow\VulnVersion\Result_bapee\P1F_100_formal_fp_guard\bapee_summary.json`

结果：

- recovered evaluation target lines：`8/30`
- operational recall：`0.2667`
- silver precision：`1.0`
- silver false positive：`0`

结论：BAPEE 可以做到保守 precision，但 recall 远不够，不能支撑 90%+ 指标目标。BAPEE 从 Step3 方法路线中移除。

### 3.6 line 之间关系的实测结论

实验：

- 脚本：`E:\AI\Agent\workflow\VulnVersion\tests\analyze_line_relationships.py`
- 输出：`E:\AI\Agent\workflow\VulnVersion\tests\line_relationships\summary.json`
- 数据集：`1128` 个 CVE，全量 9 repo。

在 Step3 中，line 之间的关系不应理解为简单时间关系，也不应直接等同于 git branch 关系。当前可用且有数据支撑的关系是：

- `line_family`：同一可比较 release stream，例如 OpenSSL mainline / fips / engine 必须分开。
- `newer_line / older_line`：同一 family 内按语义版本排序的相邻 release line。
- `line-level affected run`：一个 CVE 在 family 内命中的 affected lines 是否形成连续线段。

全量结果：

- total CVE：`1128`
- line-level contiguous CVEs：`1111`
- line-level multi-run CVEs：`17`
- max line run count：`3`
- total line gap count：`26`
- 平均 release lines/CVE：`60.36`
- 平均 affected lines/CVE：`17.21`

repo 分布：

| repo        | CVEs | avg lines | avg affected lines | line-contiguous CVEs | multi-run CVEs |
| ----------- | ---: | --------: | -----------------: | -------------------: | -------------: |
| FFmpeg      |   71 |      36.0 |              12.28 |                   71 |              0 |
| ImageMagick |   72 |       2.0 |               1.21 |                   72 |              0 |
| curl        |   68 |       1.0 |                1.0 |                   68 |              0 |
| httpd       |   30 |       7.0 |                2.8 |                   29 |              1 |
| linux       |  717 |      82.0 |              23.24 |                  717 |              0 |
| openjpeg    |   13 |      12.0 |               5.77 |                   13 |              0 |
| openssl     |   50 |      24.0 |               2.98 |                   38 |             12 |
| qemu        |   57 |      59.0 |              15.75 |                   57 |              0 |
| wireshark   |   50 |      32.0 |               10.2 |                   46 |              4 |

结论：

- line 之间确实存在可利用的同-family 版本邻接关系，因为 `1111/1128` 个 CVE 的 affected lines 在 line order 上连续。
- 该关系只能作为 active-line scheduling prior，不能作为硬推断规则，因为还有 `17` 个 multi-run CVE，主要集中在 OpenSSL 和 Wireshark。
- 对 FFmpeg、Linux、qemu、openjpeg 等 repo，同-family line run 连续性很强，后续可用 neighbor propagation 降低 active-line 成本。
- 对 OpenSSL，line_family/line_partition 必须严格处理，不能把 mainline/fips/engine 混为一条线。

### 3.7 fix commit upper-bound 硬过滤的实测结论

实验：

- 脚本：`E:\AI\Agent\workflow\VulnVersion\tests\analyze_fix_upper_bound_filter.py`
- 输出：`E:\AI\Agent\workflow\VulnVersion\tests\fix_upper_bound_filter\summary.json`
- backend：`batch-reachability`
- 数据集：`1128` 个 CVE，全量 9 repo。
- candidate 定义：release tags that do not contain any seed fix commit。

全量结果：

- full GT coverage CVEs：`1082/1128`
- has GT miss CVEs：`42`
- has unmapped CVEs：`4`
- micro GT coverage：`0.995434`
- avg tag reduction rate：`0.1752`
- avg release lines：`60.36`
- avg candidate lines after fix filter：`48.16`
- avg fully excluded lines：`12.20`

repo 结果：

| repo        | CVEs | full GT coverage | micro coverage | avg tag reduction | avg candidate lines |
| ----------- | ---: | ---------------: | -------------: | ----------------: | ------------------: |
| FFmpeg      |   71 |               67 |       0.998515 |            0.1320 |               28.03 |
| ImageMagick |   72 |               72 |       1.000000 |            0.4179 |                1.26 |
| curl        |   68 |               64 |       1.000000 |            0.1627 |                1.00 |
| httpd       |   30 |               30 |       1.000000 |            0.0392 |                7.00 |
| linux       |  717 |              682 |       0.996547 |            0.1519 |               65.29 |
| openjpeg    |   13 |               13 |       1.000000 |            0.2657 |               10.15 |
| openssl     |   50 |               50 |       1.000000 |            0.0499 |               23.70 |
| qemu        |   57 |               56 |       0.999543 |            0.3904 |               44.91 |
| wireshark   |   50 |               48 |       0.977964 |            0.1754 |               25.56 |

结论：

- fix commit 可以作为强 evidence，但不能作为硬过滤上界。
- 硬过滤平均只减少 `17.52%` tags，却导致 `42` 个 CVE 出现 GT miss；这会伤害 CVE exact accuracy 和 version recall。
- 对 ImageMagick/qemu 的 tag reduction 较明显，但对 httpd/openssl 几乎不省成本。
- 正确用法是：fix-containing tags 可降低 probe priority 或作为 fixed-side evidence；不能从 candidate space 中直接删除，也不能在 line parsing 前硬过滤 release tags。

### 3.8 论文方案核验后的 Git 筛选结论

本节回应一个关键问题：既然相关工作也使用 Git 信息筛版本，为什么 VulnVersion 不能直接硬过滤 `tags_containing(fix)`？

已核验的论文/源码依据：

- CaVulner：先定位 VIC，再计算 `tags_containing(VIC or duplicates) - tags_containing(VFC or duplicates)`。它不是只用 VFC/fix commit 做负向删除；它依赖 VIC 下界、duplicate commit、hunk hash。
- Vercation：同样基于 commit reachability，形式化为 `Vv = Vi - Vf`，其中 `Vi` 是 reachable from VIC 的 tags，`Vf` 是 reachable from VFC 的 tags。
- TDSC：构建 version tree，用 patch + developer logs 找 first/last vulnerable versions，并明确指出 patch presence 既不是充分条件也不是必要条件。没有 patch 不能直接判 vulnerable；有 patch 也可能 repatch / incomplete fix。
- How-far-are-we baseline：LLM4SZZ 的源码 `version_range_evidence.py` 使用 `git tag --contains` 做 `intro_tags - fix_tags`，而不是 `all_tags - fix_tags`。论文还指出 cross-branch patch reuse 有帮助，但会引入噪声。

因此，VulnVersion 的结论是：

- `git tag --contains <fix>` 是有效 evidence，但不是安全 candidate hard filter。
- 只使用 fix reachability 等价于只有修复上界，没有漏洞下界；在当前数据集上已经实测漏 `42/1128` 个 CVE。
- 如果没有可靠 VIC seed，正确做法不是 `all_tags - fix_tags`，而是把 fix-containing segments 标记为 lower priority / fixed-side evidence，并用少量 sentinels 做安全检查。

### 3.9 Git-guided soft pruning 的全量模拟

新增实验：

- 脚本：`E:\AI\Agent\workflow\VulnVersion\tests\simulate_git_guided_scheduler.py`
- 输出：`E:\AI\Agent\workflow\VulnVersion\tests\git_guided_scheduler_simulator\summary.json`
- 数据集：`1128` 个 CVE，全量 9 repo。
- Git backend：batch reachability，等价于对 release tags 执行 `git tag --contains <fix commit>`，但用一次反向 commit graph 传播批量计算。
- 命令：

```powershell
python tests\simulate_git_guided_scheduler.py --dataset DataSet\BaseDataSet.json --repo-root repo --out-dir tests\git_guided_scheduler_simulator --sentinel-counts 3 --fixed-segment-sentinels 0,1,2,3 --policies all_lines_asbs,hard_no_fix_filter,git_guided_soft
```

比较策略：

| policy                 | 含义                                                                                                                                                    |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `all_lines_asbs`     | 当前 ASBS-first 理论基线，所有 line active                                                                                                              |
| `hard_no_fix_filter` | 负面对照，只保留不包含 seed fix commit 的 tags                                                                                                          |
| `git_guided_soft`    | 按 line 切分 fix-containing / no-fix segments；no-fix segments 做 ASBS；fix-containing segments 不删除，只做 sentinel，若 sentinel affected 则回退 ASBS |

关键结果：

| policy                                     | avg probes/CVE | p95 | exact CVEs | FN CVEs | hard-filter miss CVEs | fixed-segment miss CVEs |  micro P |  micro R | micro F1 |
| ------------------------------------------ | -------------: | --: | ---------: | ------: | --------------------: | ----------------------: | -------: | -------: | -------: |
| `all_lines_asbs, s=3`                    |          87.20 | 172 |  1083/1128 |      39 |                     0 |                       0 | 0.999898 | 0.994656 | 0.997270 |
| `hard_no_fix_filter, s=3`                |          69.92 | 136 |  1072/1128 |      50 |                    42 |                       0 | 0.999915 | 0.995282 | 0.997593 |
| `git_guided_soft, s=3, fixed_sentinel=0` |          84.15 | 155 |  1113/1128 |       9 |                     0 |                       1 | 0.999915 | 0.999814 | 0.999865 |
| `git_guided_soft, s=3, fixed_sentinel=1` |          85.55 | 162 |  1114/1128 |       8 |                     0 |                       0 | 0.999915 | 0.999848 | 0.999882 |
| `git_guided_soft, s=3, fixed_sentinel=2` |          86.91 | 169 |  1114/1128 |       8 |                     0 |                       0 | 0.999915 | 0.999848 | 0.999882 |
| `git_guided_soft, s=3, fixed_sentinel=3` |          87.91 | 172 |  1114/1128 |       8 |                     0 |                       0 | 0.999915 | 0.999848 | 0.999882 |

repo-level 结果中，`git_guided_soft, fixed_sentinel=1` 对 FFmpeg、qemu、openjpeg 的 probe 成本有实际下降，同时修复了 hard filter 的 GT miss 问题：

| repo        | all-lines avg probes | hard-filter avg probes | soft avg probes | soft exact CVEs | soft micro F1 |
| ----------- | -------------------: | ---------------------: | --------------: | --------------: | ------------: |
| FFmpeg      |               173.90 |                 139.48 |          168.18 |           71/71 |      1.000000 |
| ImageMagick |                15.94 |                   7.78 |           12.96 |           70/72 |      0.999919 |
| curl        |                12.07 |                   9.22 |           12.22 |           64/68 |      1.000000 |
| httpd       |                38.27 |                  36.63 |           37.83 |           26/30 |      0.999198 |
| linux       |                86.17 |                  69.46 |           86.17 |         717/717 |      1.000000 |
| openjpeg    |                22.00 |                  16.15 |           20.00 |           13/13 |      1.000000 |
| openssl     |                96.12 |                  92.20 |           96.02 |           49/50 |      0.999722 |
| qemu        |               163.04 |                 114.16 |          147.35 |           57/57 |      1.000000 |
| wireshark   |               134.54 |                 110.92 |          128.24 |           47/50 |      0.999604 |

结论：

- 硬过滤确实更省 probe，但会造成 `42` 个 CVE 的 GT miss，不能作为 Step3 主策略。
- `git_guided_soft` 更符合 CaVulner/Vercation/TDSC 的思想：Git reachability 是 evidence，不能直接替代 vulnerability verdict。
- 当前最稳妥配置是 `line ASBS sentinel=3 + fixed-segment sentinel=1`。它保持全量候选空间，避免 hard deletion，同时把 fix-containing segments 的风险压到 sentinel/fallback 机制中。
- 该策略主要提升 recall / exact CVE 数，对平均 probe 成本只有小幅下降。下一步仍然需要 line risk scoring，把 active lines 从平均 `60.36` 压向 oracle affected-line 下界 `17.21`。

### 3.10 active-line scheduler 六策略全量模拟

新增实验：

- 脚本：`E:\AI\Agent\workflow\VulnVersion\tests\simulate_active_line_scheduler.py`
- 输出：`E:\AI\Agent\workflow\VulnVersion\tests\active_line_scheduler_simulator\summary.json`
- 数据集：`1128` 个 CVE，全量 9 repo。
- 命令：

```powershell
python tests\simulate_active_line_scheduler.py --dataset DataSet\BaseDataSet.json --repo-root repo --out-dir tests\active_line_scheduler_simulator --sentinel-count 3 --fixed-segment-sentinels 1
```

被比较的 6 个策略都在 active line 内使用 `git_guided_soft + ASBS`，差异只在 active-line selection：

| policy                       | 含义                                                                |
| ---------------------------- | ------------------------------------------------------------------- |
| `all_lines_soft`           | 所有 release lines 都 active，当前安全基线                          |
| `no_fix_lines_only`        | 只激活存在 no-fix tag 的 line，跳过全 fix-containing line           |
| `file_exists_endpoints`    | 若 fix-touched file 出现在 line 的 oldest/newest tag，则激活该 line |
| `file_exists_neighbor1`    | `file_exists_endpoints` 加同 family 相邻 1 条 line                |
| `file_exists_span`         | 同 family 内从最老到最新 file-exists seed 的连续 span               |
| `hybrid_fix_file_neighbor` | no-fix line 与 file-exists neighbor 的交集，进一步降成本            |

全量结果：

| policy                       | avg probes/CVE | p95 | avg active lines | exact CVEs | FN CVEs | skipped-affected-line CVEs |  micro R | micro F1 |
| ---------------------------- | -------------: | --: | ---------------: | ---------: | ------: | -------------------------: | -------: | -------: |
| `all_lines_soft`           |          85.55 | 162 |            60.36 |  1114/1128 |       8 |                          0 | 0.999848 | 0.999882 |
| `no_fix_lines_only`        |          70.90 | 139 |            48.16 |  1076/1128 |      46 |                         38 | 0.995519 | 0.997712 |
| `file_exists_endpoints`    |          57.64 | 119 |            41.66 |   981/1128 |     141 |                        134 | 0.950824 | 0.974750 |
| `file_exists_neighbor1`    |          59.01 | 123 |            42.35 |   998/1128 |     124 |                        116 | 0.957622 | 0.978310 |
| `file_exists_span`         |          57.67 | 119 |            41.69 |   982/1128 |     140 |                        133 | 0.951128 | 0.974910 |
| `hybrid_fix_file_neighbor` |          45.18 | 101 |            30.87 |   965/1128 |     157 |                        149 | 0.953107 | 0.975948 |

repo-level 关键观察：

- `file_exists_*` 策略对 qemu、linux、openjpeg 召回损失明显；说明单纯用 touched-file endpoint 做 active-line pruning 不安全。
- `hybrid_fix_file_neighbor` 可把 avg probes 降到 `45.18`，但 exact CVEs 只有 `965/1128`，不能用于主路径。
- `no_fix_lines_only` 比 hard tag filter 稍稳，但仍有 `38` 个 CVE 跳过 affected line，不能作为默认策略。
- 目前唯一达到高召回 / 高 F1 的仍是 `all_lines_soft`，但成本偏高。

结论：

- active-line scheduler 是必要方向，但当前六个 cheap deterministic 策略不能直接接入主流程。
- touched-file existence 只能作为 weak risk signal，不能作为 hard skip 条件。
- 下一步 scheduler 必须从“跳过 line”改为“分级预算 + late expansion”：先低成本 probe 高风险 lines，再根据证据扩展，而不是一次性 hard skip 低风险 lines。

### 3.11 evidence-driven staged expansion 全量模拟

新增实验：

- 脚本：`E:\AI\Agent\workflow\VulnVersion\tests\simulate_staged_expansion_scheduler.py`
- 输出目录：`E:\AI\Agent\workflow\VulnVersion\tests\staged_expansion_scheduler_simulator`
- 命令：

```powershell
python tests\simulate_staged_expansion_scheduler.py --dataset DataSet\BaseDataSet.json --repo-root repo --out-dir tests\staged_expansion_scheduler_simulator --sentinel-count 3 --fixed-segment-sentinels 1 --expansion-radius 1
```

实验性质：

- 这是 GT-oracle simulator。它用 `affected_version` 作为理想 tag verdict oracle，只衡量调度策略的理论 probe 成本和理论召回，不代表真实 agent 已经达到相同效果。
- staged expansion 的核心不是 FIC 迁移，也不是 hard skip line。
- 它先选择 seed lines，再在 seed/邻居出现 affected 证据后，沿同 family 的 `newer_line / older_line` 邻接扩展。
- 所有 line 内部仍使用 `git_guided_soft + ASBS`。

主要策略：

| policy                                | 含义                                                                                       |
| ------------------------------------- | ------------------------------------------------------------------------------------------ |
| `all_lines_soft`                    | 安全上界，所有 lines 都执行 git-guided soft ASBS                                           |
| `staged_file_neighbor1`             | touched-file endpoint lines 及其同-family 1-hop 邻居作为 seed，仅沿 affected evidence 扩展 |
| `staged_file_neighbor1_nohit_nofix` | 若第一阶段完全没有 affected hit，则 fallback 到 no-fix lines                               |
| `staged_file_or_stride3`            | file-neighbor seeds + 每个 family 每 3 条 line 一个 deterministic stride seed              |
| `staged_nofix_stride3_file`         | file-neighbor seeds + no-fix lines 上每 3 条一个 deterministic stride seed                 |
| `oracle_affected_lines`             | 理论下界，只激活 GT affected lines，用于衡量 scheduler 空间                                |

全量结果：

| policy                                | avg probes | p95 | avg seed lines | avg active lines | exact CVEs | FN CVEs |  micro P |  micro R | micro F1 |
| ------------------------------------- | ---------: | --: | -------------: | ---------------: | ---------: | ------: | -------: | -------: | -------: |
| `all_lines_soft`                    |      85.55 | 162 |          60.36 |            60.36 |  1114/1128 |       8 | 0.999915 | 0.999848 | 0.999882 |
| `oracle_affected_lines`             |      29.03 |  77 |          17.21 |            18.87 |  1114/1128 |       8 | 0.999915 | 0.999848 | 0.999882 |
| `staged_file_neighbor1`             |      60.64 | 126 |          42.35 |            43.53 |  1105/1128 |      17 | 0.999915 | 0.992948 | 0.996419 |
| `staged_file_neighbor1_nohit_nofix` |      61.77 | 127 |          42.35 |            44.18 |  1113/1128 |       9 | 0.999915 | 0.999476 | 0.999696 |
| `staged_file_or_stride3`            |      70.70 | 130 |          48.71 |            49.49 |  1114/1128 |       8 | 0.999915 | 0.999848 | 0.999882 |
| `staged_nofix_stride3_file`         |      70.53 | 130 |          48.52 |            49.31 |  1114/1128 |       8 | 0.999915 | 0.999848 | 0.999882 |

repo 级关键结果：

| repo      | `all_lines_soft` avg probes | `staged_nofix_stride3_file` avg probes | oracle avg probes | 结论                                                 |
| --------- | ----------------------------: | ---------------------------------------: | ----------------: | ---------------------------------------------------- |
| FFmpeg    |                        168.18 |                                   134.52 |             74.75 | staged 可降约 20%，但距离 oracle 仍远                |
| linux     |                         86.17 |                                    71.23 |             25.65 | line 很多但多数 singleton，仍有较大 scheduler 空间   |
| qemu      |                        147.35 |                                   108.26 |             42.28 | staged 降成本明显，但仍未接近 oracle                 |
| wireshark |                        128.24 |                                   111.84 |             52.36 | 成本下降有限，主要受多 affected lines 和长 line 影响 |
| openssl   |                         96.02 |                                    82.86 |             28.42 | OpenSSL 仍受 line_family / multi-run 复杂性影响      |

结论：

- staged expansion 是比 hard active-line pruning 更合理的方向。它不直接跳过所有低风险 line，而是用 seed + affected evidence 扩展。
- `staged_nofix_stride3_file` / `staged_file_or_stride3` 在 GT oracle 下达到与 `all_lines_soft` 相同的 micro recall / F1，同时平均 probes 从 `85.55` 降到约 `70.5`，约降低 `17.6%`。
- 更激进的 `staged_file_neighbor1_nohit_nofix` 可降到 `61.77` probes/CVE，但会多出少量 FN，特别是 OpenSSL / Wireshark / httpd 的边界型或非典型 line。
- 当前 staged expansion 还没有达到低开销目标。oracle 下界是 `29.03` probes/CVE，说明后续真正瓶颈是 line risk scoring 和 seed 覆盖，而不是 ASBS 本身。
- 该实验支持下一步实现“分级预算 + dynamic expansion”，但不能把 stride seed 当成最终算法。stride seed 是可复现实验基线，不是论文级最终设计。

### 3.12 multi-commit CVE taxonomy 与最终处理决策

新增实验：

- 脚本：临时 taxonomy 分析脚本，逻辑基于 `DataSet/BaseDataSet.json`、本地 9 个 repo 的 git history、release tag filter、`git tag --contains`、commit changed files、commit subject、merge parents。
- 输出：`E:\AI\Agent\workflow\VulnVersion\tests\multi_commit_taxonomy_analysis\summary.json`
- 数据集：`1128` 个 CVE，全量 9 repo。
- 注意：Git 命令必须带 `-c safe.directory=<repo>`，否则 Windows sandbox 用户会触发 dubious ownership，导致 commit 解析失败。

实际结果：

- multi-commit CVE 总数：`68`
- 占全量比例：`68 / 1128 = 6.03%`
- repo 分布：

| repo        | multi-commit CVEs |
| ----------- | ----------------: |
| FFmpeg      |                44 |
| httpd       |                 9 |
| qemu        |                 7 |
| wireshark   |                 3 |
| ImageMagick |                 3 |
| openjpeg    |                 2 |

commit 数量分布：

| commits per CVE | CVE count |
| --------------: | --------: |
|               2 |        32 |
|               3 |         3 |
|               4 |         3 |
|               5 |         9 |
|               6 |         9 |
|               7 |         4 |
|               8 |         6 |
|              10 |         1 |
|              15 |         1 |

taxonomy 结果：

| taxonomy                         | count | 含义                                                         |
| -------------------------------- | ----: | ------------------------------------------------------------ |
| `branch_backport_bundle_or`    |    51 | 同一修复在不同 branch / release line / backport 上的多个实例 |
| `same_component_patchset`      |    13 | 同一组件的一组 patchset，可能包含多个相关修复提交            |
| `has_wrapper_or_noise`         |     2 | merge/wrapper commit 与真实 code-changing fix 混合           |
| `multi_component_or_composite` |     2 | 多组件修复、测试 commit 与真实修复 commit 混合               |

multi-commit 子集在当前 GT-oracle staged 策略下的结果：

| policy                                | CVEs | avg probes | p95 | exact CVEs | FN CVEs | version P/R/F1            |
| ------------------------------------- | ---: | ---------: | --: | ---------: | ------: | ------------------------- |
| `all_lines_soft`                    |   68 |     138.00 | 179 |      67/68 |       1 | 1.0 / 0.999878 / 0.999939 |
| `staged_nofix_stride3_file`         |   68 |     114.69 | 179 |      67/68 |       1 | 1.0 / 0.999878 / 0.999939 |
| `staged_file_neighbor1_nohit_nofix` |   68 |     100.74 | 179 |      67/68 |       1 | 1.0 / 0.999878 / 0.999939 |

结论：

- multi-commit 子集在 GT-oracle 下不是当前 recall / F1 的主要瓶颈。
- `51/68` 个 multi-commit CVE 属于 `branch_backport_bundle_or`，占 multi-commit 子集 `75%`，占全量 `4.52%`。
- 其余 `17` 个复杂情况只占全量 `1.51%`，不应该为了它们重塑 Step3 主设计。
- 因为 Step3 已经明确 fix commits 只作为 evidence，不作为 FIC、不 hard delete tags，所以 multi-commit taxonomy 的作用应限制在 evidence normalization、scheduler priority 和 prompt organization，不应进入 affected-version planning 核心。

最终处理决策：

```text
multi-fix CVE 默认按 OR evidence bundle 处理。

fix_evidence_tags = union(tags_containing(each strong fixing commit))
fix_touched_files = union(changed_files(each strong fixing commit))
```

其中：

- `strong fixing commit`：非 merge、非 test-only、非 doc-only、存在 code-changing files 的 commit。
- `weak fixing commit`：merge/wrapper、test-only、doc/changelog-only、changed files 为空的 commit。
- strong commits 参与 `git_guided_soft` segmenting 和 touched-file seed。
- weak commits 只作为 prompt context 或 low-confidence evidence，不参与 fix-containing segment 切分。

明确不做：

- 不做复杂 AND/composite 作为默认路径。
- 不计算 `intersection(tags_containing(c1), tags_containing(c2), ...)` 作为 complete-fix hard evidence。
- 不把 multi-fix taxonomy 用来 hard skip tag / line。
- 不恢复 line-local FIC recovery 或 BAPEE。

理由：

- 主流情况是 OR backport bundle，简单 OR evidence bundle 覆盖大多数 multi-commit CVE。
- 少数 AND/composite/wrapper case 数量太少，不应影响 Step3 主架构。
- 当前更大的问题是 active-line scheduler 成本和真实 agent verdict 稳定性，而不是 multi-commit GT recall。

---

## 4. Step3 主架构

### 4.1 输入

Step3 输入应包括：

- `cve_id`
- repo path
- fix commit family
- Step1/Step2 产物，例如 RCI、patch semantics、prefetched evidence
- release tag list
- optional ground truth，用于 evaluation，不参与规划

### 4.2 release tag filter

职责：

- 通过 git tag 获取 repo 全量 tags。
- 使用 `version_registry.py` 过滤 release tags。
- 使用 `parse_version / line_key / line_family` 解析 tag 的版本语义。

注意：

- line 的划分不是直接用 git branch。
- git branch 可作为 evidence，但不是稳定的 release-version partition。很多 repo 的 branch 信号缺失、不完整或与 release tag 粒度不一致。
- 当前更贴合 affected-version 任务的是 tag-derived release line。

### 4.3 VulnTree

VulnTree 是 Step3 的核心抽象。

静态层应包含：

- `TagNode`
  - `tag`
  - `line`
  - `line_family`
  - `version_tuple`
  - `commit_sha`
  - `index_in_line`
  - `prev_tag`
  - `next_tag`
- `LineNode`
  - `line_key`
  - `line_family`
  - `tags_asc`
  - `tags_desc`
  - `older_line`
  - `newer_line`
- `VulnTreePlan`
  - `repo`
  - `cve_id`
  - `lines`
  - `ordered_lines`
  - `verification_tasks`
  - `affected_intervals`

运行态层应包含：

- tag runtime
  - `plan_status`
  - `plan_roles`
  - `verdict`
  - `verdict_source`
  - `confidence`
  - `probe_round`
  - `inferred_from`
  - `certificate_id`
- line runtime
  - `search_mode`
  - `boundary_status`
  - `contains_fix_evidence`
  - `contains_vic_evidence`
  - `no_fic_reason` 仅作为解释字段，不作为主路径依赖

设计要求：

- `newer_line / older_line` 只能在同一 `line_family` 内连接。
- OpenSSL 这类 `fips / engine / mainline` 不能混成一个全局线性链。
- cross-line early stop 不再使用。

### 4.4 line-local ASBS-first interval discovery

ASBS 当前应重新定位为：对每条 release line 找完整 affected interval，而不是依赖 FIC 找单个 boundary。

每条 line 的候选 tags 按 oldest-to-newest 排序：

```text
t0, t1, t2, ..., tn
```

基本 probe 策略：

1. probe oldest tag。
2. probe newest tag。
3. 根据端点状态选择二分或局部确认。
4. 对推断出的 affected interval 生成 certificate。
5. 只把实际调用 agent 的 tag 标记为 probed，推断 tag 标记为 inferred。

典型状态：

| endpoint pattern | 处理方式                                                                               |
| ---------------- | -------------------------------------------------------------------------------------- |
| `A ... A`      | line 可能全受影响；需要少量内部 sentinel 确认，避免中间 `N`                          |
| `N ... A`      | 二分找 first affected，得到 suffix interval                                            |
| `A ... N`      | 二分找 first not affected，得到 prefix interval                                        |
| `N ... N`      | 默认不是直接判全 N；需按 line 长度和风险选择 sentinel probe，避免 middle interval 漏报 |
| 非单调或冲突     | 标记 uncertain / non_monotone，进入局部补探，不做强推断                                |

必须支持的 interval 形态：

- full-line
- prefix-only
- suffix-only
- middle interval
- no affected
- non-contiguous / uncertain

当前数据表明 middle interval 和 non-contiguous 很少，但不能忽略。若默认只找 first affected，可能无法覆盖 prefix/middle 场景。

### 4.5 line 调度风险与初步方案

当前需要明确区分两个概念：

```text
全量构建 VulnTree != 全量 line 都调用 agent != 每条 line 都完整二分
```

必须解决的问题：

- 如果对每个 CVE 的所有 release lines 都执行完整二分，agent 调用成本会过高。
- 如果只验证包含 fix commit 的 line，recall 会明显不足，因为多数 affected lines 不包含 fix commit。
- 如果端点 `A ... A` 直接推断整条 line 受影响，可能在非连续或多区间 line 上引入 FP。
- 如果端点 `N ... N` 直接推断整条 line 不受影响，会漏掉 middle intervals；这比 `A ... A` 引入 FP 更常见。

基于 `DataSet/BaseDataSet.json` 的端点形态统计：

| pattern                      | line count |   potential error if naively inferred |
| ---------------------------- | ---------: | ------------------------------------: |
| `A ... A` 且整条 line 全 A |      18636 |        低风险，可用 sentinel 增强证书 |
| `A ... A` 但内部存在 N     |          4 |   直接全线推断会产生 9 个潜在 FP tags |
| `N ... N` 但中间存在 A     |         98 | 直接全线 N 会产生 5191 个潜在 FN tags |
| `A ... N` prefix-like      |        558 |                 需要找 upper boundary |
| `N ... A` suffix-like      |        112 |                 需要找 lower boundary |

结论：

- `A ... A` 直接推断整条 line affected 的风险存在，但规模很小；主要用 sentinel 防守即可。
- 真正影响 recall 的是 `N ... N` 中间 affected。对 `N ... N` 不能直接判整条 line not affected，必须做 middle-risk sentinel 或其他 line-risk 证据。

初步调度原则：

1. **全量建图**：每个 release tag 都进入 VulnTree，保证版本空间完整、可解释。
2. **分层激活 line**：默认不把“建图 line”全部等同于“agent active line”。后续需要 deterministic cheap prefilter / risk scoring 决定 active lines。
3. **利用同-family line 邻接作为 prior**：若同一 family 内相邻 lines 已被证实 affected，当前 line 的 active priority 应提高；若相邻 lines 均有强 not-affected evidence，当前 line 可降级为 deferred，但不能直接 hard skip。
4. **fix-containing tags 只能降权，不能删除**：fix commit 是 evidence，不是 candidate hard filter。全量实验显示硬过滤会导致 `42` 个 CVE 出现 GT miss。
5. **multi-fix 默认 OR evidence bundle**：若一个 CVE 有多个 fixing commits，默认取 strong fixing commits 的 `tags_containing` 并集和 changed files 并集。该 OR 语义只用于 evidence / priority / prompt，不用于 hard filtering。
6. **weak fixing commits 降权**：merge/wrapper、test-only、doc/changelog-only、changed files 为空的 commit 不参与 fix-containing segment 切分，只保留为 prompt context 或 low-confidence evidence。
7. **Git-guided soft pruning**：若 line 中出现 fix-containing segment，该 segment 不从 VulnTree 中删除，只做 fixed-side sentinel；若 sentinel 判 affected，则该 segment 回退 ASBS。
8. **端点优先**：active line 或 active segment 先 probe oldest/newest tag。
9. **sentinel 而非盲目二分**：
   - `A ... A`：优先做少量内部 sentinel，确认是否可以推断 full-line affected。
   - `N ... N`：优先做 middle-risk sentinel，避免漏掉 middle interval。
10. **只在边界型 line / segment 二分**：

- `N ... A`：二分 lower boundary，得到 suffix interval。
- `A ... N`：二分 upper boundary，得到 prefix interval。

11. **冲突 line 不强推断**：sentinel 或 boundary 两侧出现冲突时，标记 uncertain / non-monotone，并进入局部补探。

第一轮 GT simulator 已完成量化：

- 脚本：`E:\AI\Agent\workflow\VulnVersion\tests\simulate_step3_gt_scheduler.py`
- 默认输出：`E:\AI\Agent\workflow\VulnVersion\tests\step3_gt_scheduler_simulator\summary.json`
- no-fallback 对照输出：`E:\AI\Agent\workflow\VulnVersion\tests\step3_gt_scheduler_simulator_no_fallback\summary.json`
- 数据集：`1128` 个 CVE，全量 9 repo。
- 策略：`sentinel=0,1,2,3`；active-line 策略包括 `all_lines` 和 `oracle_affected_lines`。

关键结果：

| policy                                | avg probes/CVE | p95 | max | exact CVEs | micro precision | micro recall | micro F1 |
| ------------------------------------- | -------------: | --: | --: | ---------: | --------------: | -----------: | -------: |
| `all_lines, sentinel=0`             |          70.98 | 109 | 116 |  1021/1128 |        0.999741 |     0.912166 | 0.953947 |
| `all_lines, sentinel=1`             |          77.34 | 137 | 142 |  1062/1128 |        0.999775 |     0.978236 | 0.988888 |
| `all_lines, sentinel=2`             |          82.51 | 152 | 155 |  1072/1128 |        0.999863 |     0.986979 | 0.993379 |
| `all_lines, sentinel=3`             |          87.20 | 172 | 178 |  1083/1128 |        0.999898 |     0.994656 | 0.997270 |
| `oracle_affected_lines, sentinel=3` |          25.98 |  76 | 160 |  1083/1128 |        0.999898 |     0.994656 | 0.997270 |

解释：

- `all_lines + sentinel=3` 说明：如果所有 release lines 都 active，理论指标很高，但平均 `87.20` probes/CVE，FFmpeg、qemu、wireshark 成本偏高。
- `oracle_affected_lines + sentinel=3` 说明：如果未来 line scheduler 能准确激活真正相关 lines，理论成本下界约 `25.98` probes/CVE。
- `sentinel=0` recall 只有 `0.912166`，说明仅靠端点不够，会漏 middle/small interval。
- `sentinel=3` 的 recall 达到 `0.994656`，但成本上升到 p95 `172`，证明必须继续做 deterministic line risk scoring / prefilter，不能简单让所有 lines active。
- fallback scan conflict 只影响少数 `A...A` 冲突 line：no-fallback 时 `all_lines + sentinel=3` micro F1 为 `0.996879`，fallback 后为 `0.997270`，成本几乎不变。

第二轮 Git-guided simulator 已完成量化：

- 脚本：`E:\AI\Agent\workflow\VulnVersion\tests\simulate_git_guided_scheduler.py`
- 默认输出：`E:\AI\Agent\workflow\VulnVersion\tests\git_guided_scheduler_simulator\summary.json`
- 策略：`all_lines_asbs`、`hard_no_fix_filter`、`git_guided_soft`

关键结果：

| policy                                     | avg probes/CVE | p95 | exact CVEs | FN CVEs | micro precision | micro recall | micro F1 |
| ------------------------------------------ | -------------: | --: | ---------: | ------: | --------------: | -----------: | -------: |
| `all_lines_asbs, s=3`                    |          87.20 | 172 |  1083/1128 |      39 |        0.999898 |     0.994656 | 0.997270 |
| `hard_no_fix_filter, s=3`                |          69.92 | 136 |  1072/1128 |      50 |        0.999915 |     0.995282 | 0.997593 |
| `git_guided_soft, s=3, fixed_sentinel=1` |          85.55 | 162 |  1114/1128 |       8 |        0.999915 |     0.999848 | 0.999882 |

结论：

- `git_guided_soft` 是当前最适合接入 Step3 的 Git 筛选方式。
- 它不删除 fix-containing tags，因此不会重复 hard filter 的 `42` 个 CVE miss 问题。
- 它把 fix evidence 转化为 fixed-side sentinel + fallback ASBS，符合“Git 证据辅助调度，agent/verifier 判定漏洞”的架构边界。

repo 维度成本风险：

| repo        | avg probes/CVE under `all_lines,sentinel=3` | p95 | micro F1 |
| ----------- | --------------------------------------------: | --: | -------: |
| FFmpeg      |                                        173.90 | 177 | 0.999841 |
| qemu        |                                        163.04 | 163 | 1.000000 |
| wireshark   |                                        134.54 | 138 | 0.999604 |
| openssl     |                                         96.12 |  98 | 0.999722 |
| linux       |                                         86.17 |  88 | 1.000000 |
| httpd       |                                         38.27 |  42 | 0.999198 |
| openjpeg    |                                         22.00 |  22 | 1.000000 |
| ImageMagick |                                         15.94 |  22 | 0.995618 |
| curl        |                                         12.07 |  17 | 0.977363 |

当前结论：

- 全量 line active 是可运行上界，但不是最终低开销方案。
- 每条 line 完整二分不是当前策略；当前模拟主要是 endpoint + sentinel + 只在边界型 line 二分。
- 下一步核心不是回到 FIC/BAPEE，而是实现 **deterministic line risk scoring / prefilter**，把实际 active lines 从平均 `60.36` 条/CVE 压向 oracle 下界的 `17.21` 条/CVE。

### 4.6 FIC/VIC 的新角色

FIC/VIC 不再是 Step3 的主路径依赖。

允许使用：

- 如果某个 fix commit 自然被 tag 包含，可作为 fixed evidence。
- 这些 evidence 可以影响 probe priority，但不能决定 line 跳过，也不能替代 agent verdict / interval certificate。

禁止使用：

- 不再为每条 line 强行恢复 line-local FIC。
- 不再用 BAPEE 把 seed fix commit 迁移到其他 line。
- 不假设 `rci.json` 提供 `vuln_commit`；当前 RCI 不作为 VIC seed 来源。
- 不再把 `no FIC` 解释成“不需要验证”。
- 不再用 FIC 作为 affected interval 的唯一上界。

---

## 5. 当前保留与剔除

### 5.1 保留

- `VulnTree`
- release tag filtering
- tag-derived release line
- `line_family / line_partition`
- line-local ASBS-first
- Git-guided soft pruning
- dynamic runtime state
- probed / prefiltered / inferred / agent_error artifact 分桶
- explicit tags 模式
- `frontiers` 兼容输出字段
- `repo.py` 中通用 git helper，例如 `list_tags(max_tags=...)`

### 5.2 剔除

- BAPEE 作为 Step3 方法模块
- line-local FIC recovery
- fix duplicate expansion 作为主路径
- VIC commit discovery 作为主路径
- repo-level global ASBS
- global FIC candidate 作为默认 planning
- fix-containing tags hard deletion
- legacy full scan
- legacy `max_tags` 截断控制
- legacy `unknown_mode`
- legacy `older_line_window`
- legacy `cross_line_early_stop_k`
- cross-line early stop heuristic

说明：源码中若仍保留 BAPEE evaluator 或历史实验脚本，应视为 archived experiment，不应被新的 Step3 主流程调用。

---

## 6. Artifact 规范

Step3 输出必须支持论文级解释和消融。

### 6.1 必须输出

- `tag_plan.json`
  - 兼容旧流程，但内容应对应当前 VulnTree plan。
- `vuln_tree.json`
  - 记录静态图结构。
- `vuln_tree_runtime.json`
  - 记录 runtime state。
- `line_intervals.json`
  - 记录每条 line 的 affected interval、probe tags、certificate、uncertainty。
- `per_tag_verdict.jsonl`
  - 只记录真实 probe、prefilter、inferred rows、agent_error rows。
- `eval.json`
  - 区分 probed / prefiltered / inferred / unmapped / agent_error。

### 6.2 verdict_source

| source                | 含义                     | 是否计入普通 CM                             |
| --------------------- | ------------------------ | ------------------------------------------- |
| `agent`             | agent 实际判别           | 是                                          |
| `prefilter`         | deterministic prefilter  | 是，但需单独统计                            |
| `inferred_interval` | ASBS certificate 推断    | 是，但需单独统计                            |
| `agent_error`       | 超时、解析失败、执行错误 | 不污染 precision，单独计入 execution FN/UNK |

---

## 7. 下一步优先级

### P0 已完成第一轮：ASBS-first GT simulator

目的：在不调用 agent 的情况下，用 ground truth 模拟每条 line 的 probe / inference 策略，先证明算法在 1128 CVE 上理论可达高 recall / precision。

当前状态：

- 已新增：`E:\AI\Agent\workflow\VulnVersion\tests\simulate_step3_gt_scheduler.py`
- 已完成全量 1128 CVE 模拟。
- `all_lines + sentinel=3` 达到 micro F1 `0.997270`，但平均 `87.20` probes/CVE，p95 `172`。
- `oracle_affected_lines + sentinel=3` 达到同样理论指标，平均 `25.98` probes/CVE。

结论：

- ASBS-first interval discovery 的理论效果足够进入下一阶段。
- 当前不能直接实现 all-lines active，否则 FFmpeg/qemu/wireshark 的 token/time 成本会偏高。
- 下一步必须先做 line scheduler，把 active lines 从“全量 release lines”压缩到“高风险相关 lines”。

### P1：deterministic line risk scoring / prefilter

任务：

- 输入仍是 VulnTree 全量 lines。
- 输出是 active lines、deferred lines、skipped-with-certificate lines。
- 目标是接近 `oracle_affected_lines` 的成本下界，同时不能明显损失 recall。
- prefilter 必须 deterministic，不依赖 LLM 规划。
- 可用信号包括 touched files/symbols 是否存在、patch context 是否存在、RCI 证据是否可定位、line_family、自然 fix containment evidence。
- 当前最优先接入的 Git 信号是 `git_guided_soft`：
  - batch reachability 计算 `tags_containing(seed fix commits)`；
  - 在每条 line 内切分 fix-containing / no-fix segments；
  - no-fix segments 进入 ASBS；
  - fix-containing segments 做 `fixed_segment_sentinel=1`；
  - sentinel affected 时回退 ASBS；
  - sentinel clean 时只作为 deferred/fixed-side certificate，不从 VulnTree 删除节点。

验收标准：

- 对 1128 CVE 的 GT simulator，`git_guided_soft` 必须不低于当前结果：micro recall `0.999848`、micro F1 `0.999882`、FN CVEs `<= 8`。
- 接入真实 verifier 后，不能把 sentinel clean 的 fixed segment 直接计入 ordinary TN，必须标注为 `prefilter/deferred_fixed_segment`，用于消融统计。
- 若某个 fix-containing segment 后续被 agent 证明 affected，必须触发 fallback ASBS，并记录 `incomplete_or_repatch_suspected`。

P1 当前负结果：

- `file_exists_endpoints`、`file_exists_neighbor1`、`file_exists_span`、`hybrid_fix_file_neighbor` 均已在 1128 CVE 上模拟。
- 它们能降低 probes，但会跳过 affected lines，micro recall 只有 `0.950824~0.957622`，不能满足 90%+ CVE exact 目标。
- 因此 P1 不能采用 hard active-line pruning。

P1 当前正向结果：

- `simulate_staged_expansion_scheduler.py` 已在 1128 CVE 上模拟 evidence-driven staged expansion。
- `staged_nofix_stride3_file` 和 `staged_file_or_stride3` 在 GT oracle 下达到与 `all_lines_soft` 相同的 micro recall `0.999848` 和 micro F1 `0.999882`。
- 平均 probes 从 `85.55` 降到 `70.53~70.70`，p95 从 `162` 降到 `130`。
- 这证明 staged expansion 可以安全降低一部分成本，但距离 oracle affected-line 下界 `29.03` 仍很远。

P1 下一步应改成 staged scheduling 的工程实现与继续优化：

- 第一轮：高风险 lines 低成本 probe。高风险信号包括 touched-file endpoint、no-fix segment、同-family stride seed、历史 artifact 中的 path/symbol evidence。
- 第二轮：若证据显示 affected run 未闭合，则沿同 family 的 `newer_line / older_line` 扩展。
- 第三轮：只对 remaining uncertain lines 做 sentinel，而不是一开始全量 sentinel。
- 第四轮：对 OpenSSL / Wireshark / httpd 的 FN case 建立 case dump，专门优化 non-standard line family、多 run、短 affected interval。
- 当前不能把 stride seed 作为最终论文方法；stride seed 只是可复现 baseline。最终需要把 stride 替换为更强的 deterministic line risk scoring。

### P1-M：multi-fix evidence normalization

任务：

- 在 Step3 evidence 层实现轻量 multi-fix normalization。
- 默认将 multi-fix CVE 的 strong fixing commits 视为 OR evidence atoms。
- 过滤或降权 weak commits：
  - merge / wrapper commit；
  - test-only commit；
  - doc / changelog-only commit；
  - changed files 为空的 commit。
- 输出每个 CVE 的 `fix_evidence_bundle`，至少包含：
  - `raw_commits`
  - `strong_commits`
  - `weak_commits`
  - `fix_evidence_tags`
  - `fix_touched_files`
  - `taxonomy_hint`
  - `confidence`

约束：

- 不做复杂 AND/composite 默认路径。
- 不把 taxonomy 用作 hard skip。
- 不恢复 line-local FIC recovery。
- 不恢复 BAPEE。
- 该模块只服务 `git_guided_soft`、staged scheduler 和 agent prompt organization。

验收标准：

- 68 个 multi-commit CVE 全部可生成 `fix_evidence_bundle`。
- `branch_backport_bundle_or` 覆盖为默认 OR 语义。
- wrapper/test/doc-only commit 不污染 touched-file seed。
- 在 GT simulator 中，multi-commit 子集不低于当前结果：`staged_nofix_stride3_file` exact `67/68`、version F1 `0.999939`。

### P2：把 ASBS-first 接入 Step3 主路径

任务：

- 修改 planner，使 verification task 以 line interval discovery 为单位。
- 修改 verifier，使其按 line 执行 endpoint/sentinel/binary probes。
- 接入 `git_guided_soft`，但不得实现 hard deletion。
- 写入 `line_intervals.json`。
- 回写 `vuln_tree_runtime.json`。
- 保留 explicit tags 模式。

### P3：补强 interval precision guard

任务：

- 对 `A ... A` 全线推断增加内部 sentinel。
- 对 `N ... N` 增加 middle-interval 风险探测。
- 对 boundary 两侧增加 confirm probe。
- 对 non-monotone line 做局部补探，不做强推断。

### P4：处理少数非连续 line

任务：

- 专门分析 7 个 non-contiguous CVE。
- 判断是数据集标注问题、版本解析问题、还是漏洞真实多区间。
- 对真实多区间支持 multi-interval output。

### P5：1128 CVE 全量评估

任务：

- 运行全量 Step3。
- 输出 repo-level / CVE-level / version-level 指标。
- 输出消融：
  - line-local ASBS-first
  - ASBS-first + sentinel
  - ASBS-first + prefilter
  - explicit tags baseline
  - global FIC negative baseline

---

## 8. 论文表述边界

当前可以表述：

- Step3 将 affected-version identification 建模为 release-version graph 上的 line-local interval discovery。
- 数据集证据显示 affected versions 在 release line 内高度连续。
- repo-level global ordering 会产生大量 `A-N-A`，不适合作为默认二分空间。
- fix commit 在多数 affected lines 上不可见，因此 line-local FIC recovery 不适合作为主路径。
- agent 被限制为 tag verdict 判别器，规划与推断由 deterministic algorithm 完成。

当前不能表述：

- BAPEE 是 Step3 的贡献点。
- Step3 已经依赖 line-local FIC recovery 提升 recall。
- 全局 ASBS 可以替代 release line。
- FIC/VIC commit 可以稳定决定每条 line 的 affected boundary。
- 未经 1128 CVE 实测的策略能达到 90%+。

---

## 9. 当前最终判断

Step3 的正确方向不是继续扩大 FIC/VIC commit recovery，而是回到 affected-version 空间本身：构建 VulnTree，按 release line 做 ASBS-first affected interval discovery，再用 artifact 和 runtime state 保证可解释、可消融、可复现。

BAPEE / line-local FIC recovery 已从当前 Step3 方法路线中剔除。后续所有优化应围绕 line-local interval discovery 的 recall、precision 和 probe cost 展开。
