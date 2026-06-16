# VulnVersion Step3 架构图说明

图文件：`E:\AI\Agent\workflow\SystemDesign\Architecture\Develop\step3_architecture.mmd`

## 1. 当前真实运行路径

当前 Step3 默认路径已经接入源码：

```text
Input(CVE + repo + fixing_commits + optional evidence_path)
  -> release tag discovery
  -> version_registry release filter
  -> line/family parsing
  -> build VulnTree
  -> git_reachability.batch_tags_containing
  -> line_scheduler.compute_seed_lines
  -> line_scheduler.run_staged_scheduler
  -> asbs_line.run_asbs_segment / run_fixed_segment_sentinel
  -> AgentRuntime.run_json tag verdict
  -> artifact_eval.evaluate_step3_output
  -> Artifacts
```

真实运行中，agent 只负责对被调度到的 probe tag 输出 `AFFECTED / NOT_AFFECTED`。agent 不决定 tag plan，不读取 GT，不做 commit-level boundary planning。

## 2. 当前默认参数

当前源码中的默认配置为：

```text
NN_SENTINEL_COUNT = 3
AA_SENTINEL_COUNT = 1
FIXED_SEG_SENTINEL = 1
expansion_radius = 1
strategy = staged_nofix_stride3_file
```

这些参数来自 `asbs_line.py`、`line_scheduler.py` 和 `verify_tags.py`，并已在 `step3.md` 中登记。

## 3. 三条路径的区别

- 默认真实路径：使用 VulnTree、git-guided scheduler、ASBS 和 agent verdict，输出正式 artifacts。
- explicit tags 路径：调用方直接传入 tags，跳过 scheduler，只对指定 tags 调 agent，并进入同一 artifact/eval 层。
- simulator 验证路径：使用 GT oracle 或 module-backed simulator 做参数验证和策略评估。该路径不参与真实 planning，也不进入 agent prompt。

## 4. Artifact 输出

图中展示的核心输出包括：

- `tag_plan.json`
- `vuln_tree.json`
- `vuln_tree_runtime.json`
- `scheduler_plan.json`
- `line_intervals.json`
- `per_tag_verdict.jsonl`
- `per_tag_verdict.csv`
- `eval.json`

## 5. verdict_source / bucket

当前 artifact 层需要区分：

- `agent`
- `inferred_interval`
- `inferred_no_affected`
- `inferred_full_line_affected`
- `fixed_segment_clear`
- `aa_conflict_scan`
- `agent_error`
- `unresolved`
- `deferred`

这些 bucket 用于区分真实 agent 判别、ASBS 推断、Git fixed-side clear、执行失败以及未解析状态，避免把系统推断伪装成 agent verdict。

## 6. 当前源码接入状态

截至当前检查，Step3 已按图中主路径接入源码：

- `verify_tags.py` 默认路径调用 `git_reachability.py`、`line_scheduler.py`、`asbs_line.py`、`artifact_eval.py`。
- 旧的 BAPEE、commit equivalence、旧 boundary search 文件已从源码中删除。
- `evidence_path` 只作为 agent prompt context，不参与 Step3 planning。
- `GT` 只用于 simulator 和 final evaluation，不进入真实 Step3 planning 或 prompt。

当前测试状态：`python -m pytest tests -q` 为 `155 passed`。
