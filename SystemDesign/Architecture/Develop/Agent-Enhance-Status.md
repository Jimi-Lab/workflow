# VulnVersion Agent Enhancement Status

本文档用于动态维护 `Agent-Enhance.md` 的源码落地状态。每次修改 Agent runtime、prompt、memory、skills、trace 或 backend adapter 后，都需要同步更新本文档，并运行：

```cmd
cmd /c "python check_agent_enhance_status.py"
```

运行目录：

```text
E:\AI\Agent\workflow\VulnVersion\tests
```

## Status Scale

| Score | 含义 | 证据要求 |
|---|---|---|
| 0/5 | 未开始 | 只有想法或未写入文档 |
| 1/5 | 设计或脚手架 | 有文档、目录、schema、占位类，但未接入主流程 |
| 2/5 | 静态可导入 | import/compile 通过，但主流程未使用 |
| 3/5 | 主流程静态接入 | main 或 Stage1/2/3 已调用，静态检查通过 |
| 4/5 | 小样本运行验证 | 至少 1 个 CVE 的真实 OpenCode run 通过并产出 artifacts |
| 5/5 | 批量实验验证 | 多 CVE / 多 repo 评估通过，有指标和失败分析 |

## Current Status

| 模块 | 当前分数 | 当前状态 | 已完成 | 未完成 |
|---|---:|---|---|---|
| Harness scaffold | 3/5 | static integrated | 新增 `vulnversion/agent_harness`，包含 base/task/result/service/trace/json_utils/config、runtimes、prompts、memory、skills；`AgentService` 已作为透明 `run_json` 代理接入 worker 主流程，记录 runtime manifest、known sessions、trace 和调用级 artifacts | 尚未进入 memory/skills 注入 phase；尚未做真实 CVE 端到端 smoke run |
| AgentTask explicitization | 3/5 | Stage1/2/3 static integrated | Stage1 chunk role、Stage2 RCI induction、Stage3 single-tag verdict 均已构造 `AgentTask` 并优先走 `AgentService.run_task()`；均记录 `judgement_only` 与阶段专用 `forbidden_context` | 尚未用真实 CVE 小样本逐阶段验证全部 AgentTask 路径 |
| OpenCodeRuntime | 3/5 | adapter live validated, CVE not validated | `main.py` 通过 `OpenCodeRuntime.from_config()` 创建 agent；Stage1/2/3 依赖 `AgentRuntime`；`OpenCodeRuntime.diagnostics()` 可记录 health、provider/model、native `.opencode/skills`、native tools 和 readonly permissions | 本轮不做全量 CVE；后续只允许先做小样本/单 tag 验证 |
| CodexRuntime | 1/5 | reserved only | 已有 reserved runtime，明确不加载 `.opencode/skills` | 未实现 CLI/SDK 调用、权限、schema、trace |
| ClaudeRuntime | 1/5 | reserved only | 已有 reserved runtime，明确不加载 `.opencode/skills` | 未实现 CLI/SDK 调用、权限、schema、trace |
| ReplayRuntime | 3/5 | local replay capable, not batch validated | `ReplayRuntime` v1 可从 `trace_path` 或 `calls_index_path` 定位 `agent_calls/index.jsonl`，按 stage/task/prompt provenance/prompt_hash 匹配并读取 parsed output；未命中抛 `ReplayMissError` | 尚未对历史 CVE trace 做覆盖率验证；不能作为批量实验 backend 声明 |
| Trace | 3/5 | call artifacts static integrated | `AgentService.run_json()` 已记录 `agent_trace.jsonl`，并落盘 `agent_calls/<trace_id>.parsed.json`、prompt/system artifact 和 `index.jsonl`；trace 增加 parsed/prompt/system path；写入失败只记录 `artifact_write_error` | 尚未完成真实 CVE live validation；不保存 raw model output |
| Prompt provenance | 3/5 | static integrated v0/v1 | 新增 `PromptSpec` / `PromptProvenance`；Stage1/2 已登记为 v0，Stage3 已登记 `stage3_verdict_v0=legacy_navigation` 与 `stage3_verdict_v1=target_tag_theorem_judge`；trace 写入 prompt_name、prompt_version、schema_name、prompt_builder、prompt_hash；Stage3 已完成真实小样本 A/B | 尚未做模板迁移；Stage1/2 prompt 尚未 A/B |
| Harness mode config | 3/5 | env config and manifest ready | `AgentHarnessConfig` 支持 `memory_mode`、`skill_mode`、`replay_mode`，可由 `VV_MEMORY_MODE`、`VV_SKILL_MODE`、`VV_REPLAY_MODE` 配置；`agent_runtime.json` 可记录 harness mode | `main.py` 尚未按 mode 执行 memory/skills/replay 策略 |
| Injection audit stub | 3/5 | trace metadata stub only | `AgentService.run_json()` 默认记录 `memory_mode`、`skill_mode`、`replay_mode`、`retrieved_memory_ids`、`selected_skills`、`suppressed_skills`、`injection_policy` | 当前不检索 memory，不注入 canonical skills，不改变 prompt 行为 |
| Self-evolution case pack | 2/5 | offline case pack builder local | 新增 `vulnversion/self_evolve` 和 `tests/build_agent_enhance_cases.py`；可从 `Result/*/*` 离线生成 `Result_agent_enhance_cases/<enhancement_id>/`，包括 `case_index.jsonl`、`hypothesis.md`、`replay_summary.json`、`small_sample_summary.json`、improved/regression/unchanged JSONL 和 per-case source manifest；区分 agent judge、legacy agent judge 与 deterministic non-agent | 当前仍是 hypothesis evidence；未做 ReplayRuntime batch replay、小样本 OpenCode 验证；不允许启用 `read_only memory injection` |
| Prompt templates | 4/5 | Stage3 v1 default after 8-CVE cost gate | 新增三阶段模板占位；Stage3 已新增 Python prompt builder `target_tag_theorem_judge`，保持输出 schema 不变；v1 prompt 已压缩并显式要求 `git -C <repo_path>`；8-CVE Stage3-only cost gate 中 v1 为 10 improved / 0 regression，且完整 message JSON 体量下降 | 尚未迁移为模板文件；v0 仍保留为 deprecated baseline，等待更大样本后物理删除 |
| Memory | 2/5 | candidate store local | 新增 `memory_candidates.py`、`memory_store.py` 和 `tests/build_memory_candidates.py`；可从 case pack 生成 `Result_agent_enhance_memory/<enhancement_id>/memory_candidates.jsonl` 与 `memory_summary.json`；支持 FailureMemory、RepoMemory、RCIMemory、SkillMemory candidate | 未接入检索、注入、更新、晋升；candidate 默认 `injection_allowed=false` |
| Self-evolution blocking gates | 2/5 | local blocking gates | 新增 `leakage_gate.py`、`promotion_gate.py` 和 `tests/check_memory_candidates.py`；gate 可输出 `gated_memory_candidates.jsonl` 与 `gate_summary.json`；当前真实 case pack 默认全部 blocked | 未做 ReplayRuntime batch gate、小样本 OpenCode gate；不能启用 read-only memory |
| Skills | 2/5 | OpenCode native v2, canonical still off | `.opencode/skills/git-navigation` 已升级为 OpenCode-native judge-only workflow；`cwe-skills` 新增 static base + learned overlay 架构；新增 `tests/check_opencode_skills.py` 审计 OpenCode native skills | 未实现 canonical verified skill registry、selector、注入与 verifier gate；learned overlay 尚无 verified rule |
| Backend-specific skill boundary | 3/5 | OpenCode native inventory and audit wired | `Agent-Enhance.md` 已说明 `.opencode/skills` 只属于 OpenCode；`OpenCodeRuntime.diagnostics()` 已能盘点 OpenCode native skills/tools；本地 audit 可检查 `.opencode/skills` 结构和数据集 CWE coverage | 未实现 canonical skill registry 到 backend-native skill 的转换 |
| Stage3 runtime cleanup | 3/5 | static integrated | 已从 `main.py`、`run_stage3()` 和 `verify_tags()` 删除不生效的 `--all-tags`、`--max-tags`、`--early-stop-n`、`early_stop_n`、`bisect_enabled` 兼容路径；状态检查要求废弃参数不得回归 | 这不是性能优化；真实 Stage3 成本控制仍需在 deterministic tag plan / probe budget 层实现 |
| Stage3 prompt v1 A/B | 4/5 | 8-CVE Stage3-only OpenCode cost gate validated | `main.py --stage3-prompt-version {v0,v1}` 已接入；默认已切到 v1；v0 已标记为 deprecated baseline；`tests/evaluate_agent_enhancement.py` 已修复 session-wrapped tool-call 统计、UNKNOWN/ERROR improved 分类，并新增完整 message JSON 字符统计；8-CVE/40-tag A/B 结果为 v1 improved=10、regression=0、UNKNOWN 11->1、latency 127.68s/tag->72.84s/tag、tool calls 37.35/tag->17.23/tag、message JSON 323132 chars/tag->84821 chars/tag、JSON parse failure=0 | v1 仍有 1 个 timeout；v0 暂不物理删除，等待更大样本或正式 BaseDataOrder 子集验证 |

最近验证：

- 2026-05-02：OpenCode server 已可达，`AgentService + OpenCodeRuntime` 极简 live probe 成功，输出写入 `Result/_agent_harness_smoke/agent_trace.jsonl`。该验证只证明 harness trace 真实落盘，不等同于 CVE smoke run。
- 2026-05-02：OpenCode adapter manifest live probe 成功，`Result/_agent_harness_smoke/agent_runtime.json` 记录 server health、OpenCode agents、`cwe-skills`、`git-navigation`、`git`/`list_tags` tools 和 readonly permissions。该验证不进入 CVE pipeline。
- 2026-05-02：`tests/check_agent_enhance_status.py` 已扩展 prompt provenance、Stage1 AgentTask 和 ReplayRuntime v1 边界检查，当前 `21 passed, 0 failed`。
- 2026-05-02：非 CVE prompt provenance live probe 成功，`agent_trace.jsonl` 已真实写入 `prompt_name`、`prompt_version`、`schema_name`、`prompt_builder` 和 `prompt_hash`。
- 2026-05-02：地基层状态检查扩展到 trace-linked artifacts、ReplayRuntime v1、本地 replay probe、Stage2/Stage3 AgentTask、harness mode config 和 injection audit stub，当前 `29 passed, 0 failed`。
- 2026-05-02：`compileall` 已覆盖 `vulnversion/agent_harness`、Stage2 RCI、Stage3 verify_tags，编译通过。
- 2026-05-02：非 CVE OpenCode live probe 成功，trace_id=`probe-becb54576cdc42c69d2088c3ce74a61f`；`Result/_agent_harness_smoke/agent_calls/` 已生成 parsed/prompt/system artifacts，trace 记录 artifact path、prompt provenance 和 injection audit 字段。
- 2026-05-02：ReplayRuntime local replay probe 成功，使用上一步生成的 `Result/_agent_harness_smoke/agent_calls/index.jsonl` 命中相同 prompt hash 并回放 parsed JSON；该验证不调用 OpenCode。
- 2026-05-03：Phase C v0 编译通过：`python -m compileall vulnversion\self_evolve tests\build_agent_enhance_cases.py tests\check_agent_enhance_status.py`。
- 2026-05-03：`tests/build_agent_enhance_cases.py --enhancement-id stage3_agent_judge_failures_v0 --limit 20 --agent-only` 成功生成 agent judge case pack：20 cases，FN=12，FP=8，状态仍为 `hypothesis`。
- 2026-05-03：`tests/check_agent_enhance_status.py` 已扩展 self-evolution case pack schema、builder、failure attribution boundary 和本地临时 case pack 验证，当前 `34 passed, 0 failed`。
- 2026-05-04：`tests/check_opencode_skills.py` 通过，识别 2 个 OpenCode native skills；dataset CWE coverage 为 119/122，CWE-275、CWE-310、CWE-840 缺少 static by-id 文件，当前作为 warning 处理。
- 2026-05-04：`tests/build_memory_candidates.py --enhancement-id stage3_agent_judge_failures_v0 --apply-gates` 生成 43 条 memory candidates：FailureMemory 20、RCIMemory 19、RepoMemory 2、SkillMemory 2；promotion gate 结果为 blocked 43、injection_allowed 0。
- 2026-05-04：`tests/check_memory_candidates.py` 通过 5 个 gate fixture：missing replay blocked、leakage blocked、single-case SkillMemory blocked、repeated SkillMemory without replay/sample blocked、complete fixture can pass。
- 2026-05-04：`tests/check_agent_enhance_status.py` 已扩展 OpenCode skills audit、git-navigation v2、CWE learned overlay、memory candidate store、leakage/promotion gate 和本地 gate 验证，当前 `42 passed, 0 failed`。
- 2026-05-06：删除 Stage3 废弃 CLI/runtime 参数后，`tests/check_agent_enhance_status.py` 新增 main CLI 与 Stage3 signature 清理检查，验证结果为 `44 passed, 0 failed`。
- 2026-05-11：从 `E:\AI\Agent\workflow\VulnVersion\tests` 运行 `cmd /c "python -m compileall ..\main.py ..\vulnversion\agent_harness\prompts ..\vulnversion\stage3_verify check_agent_enhance_status.py evaluate_agent_enhancement.py"`，编译通过。
- 2026-05-11：`cmd /c "python evaluate_agent_enhancement.py --self-test"` 通过，fixture 能输出 `agent_enhance_eval_summary.json`、improved/regression/unchanged cases 和 cost report。
- 2026-05-11：`cmd /c "python check_agent_enhance_status.py"` 验证结果为 `47 passed, 0 failed`，新增 Stage3 prompt v1 和 A/B eval 静态检查。
- 2026-05-11：修复 Stage3 v1 `n0.11.4` ERROR regression 后，单 tag 验证结果为 `run_status=OK`、`verdict=AFFECTED`、latency 约 76.55s、prompt chars 7668；修复点是 prompt 显式要求 `git -C <repo_path>` 访问 `repo/<repo>`。
- 2026-05-11：完成 3-CVE Stage3-only OpenCode A/B：FFmpeg/CVE-2020-13904、linux/CVE-2022-0286、linux/CVE-2022-0433，各 5 个 tag；v1 相比 deprecated v0 为 improved=3、regression=0、unchanged=12，UNKNOWN 3->0，平均 latency 111.17s/tag->52.84s/tag，平均 tool calls 32.87/tag->15.33/tag，JSON parse failure=0。
- 2026-05-11：修复 `tests/evaluate_agent_enhancement.py` 的两个评估问题：正确解析 `opencode_messages_all.jsonl` 的 session-wrapped `messages` 格式；将 baseline UNKNOWN/ERROR 到 candidate correct 的变化计入 improved cases。
- 2026-05-13：完成 8-CVE Stage3-only cost gate：FFmpeg/CVE-2020-12284、FFmpeg/CVE-2020-13904、linux/CVE-2022-0171、CVE-2022-0185、CVE-2022-0264、CVE-2022-0286、CVE-2022-0322、CVE-2022-0433，共 40 tags；v1 为 improved=10、regression=0、UNKNOWN 11->1、latency 127.68s/tag->72.84s/tag、tool calls 37.35/tag->17.23/tag、完整 message JSON 323132 chars/tag->84821 chars/tag、JSON parse failure=0。
- 2026-05-13：Stage3 默认 prompt version 已从 v0 切换为 v1；v0 保留为显式 `--stage3-prompt-version v0` deprecated baseline，不再作为默认主路径。

## Completed Improvements

1. 解耦入口：Stage1/2/3 不再直接类型依赖 `OpenCodeAgent`。
2. OpenCode 兼容层：`OpenCodeRuntime` 复用现有 OpenCode server / OpenCodeAgent。
3. Backend 预留：Codex/Claude/Replay runtime 文件存在，但明确未接入。
4. Skill 边界：区分 `.opencode/skills`、VulnVersion canonical skills、Codex/Claude native skills。
5. 文档同步：`Agent-Enhance.md` 和 `step3.md` 已更新。
6. 静态验证：compile/import/main help 已通过。
7. `AgentService` 已透明接入 `run_json`，并通过 OpenCode live probe 验证 trace 落盘。
8. OpenCode adapter 已写入 `agent_runtime.json`，支持 native skills/tools/permissions 盘点；`AgentService` 已跟踪 known sessions，并支持导出所有已知 OpenCode session messages。
9. Prompt provenance 已静态接入，当前 Python prompt builder 已作为 v0 baseline 进入 trace。
10. Stage1/Stage2/Stage3 已迁移到 `AgentTask` 优先路径，保留 direct runtime 回退兼容。
11. ReplayRuntime v1 已可从 `agent_calls/index.jsonl` 本地回放 parsed JSON，但仍未 batch validated。
12. Trace-linked parsed output artifact 已接入 `AgentService.run_json()`，包括 parsed/prompt/system 文件和 `index.jsonl`。
13. Harness mode config 已接入 runtime manifest，injection audit stub 已接入 trace metadata。
14. Phase C v0 已接入离线 case pack builder，可将历史 `eval.json` / `per_tag_verdict.jsonl` / `rci.json` 转换为 self-evolution hypothesis evidence。
15. OpenCode-native skills audit 已接入，可检查 git-navigation、cwe-skills、dataset CWE static coverage 和 learned overlay 地基。
16. `.opencode/skills/git-navigation` 已升级为 judge-only v2 workflow，强调 tag snapshot、rename/topology 检查、evidence discipline 和 failure-triggered workflow。
17. `.opencode/skills/cwe-skills` 已新增 learned overlay 目录，static base knowledge 与 self-evolution overlay 分离。
18. Memory candidate store 与 leakage/promotion blocking gates 已落地，当前所有真实 candidates 默认 blocked，不进入 prompt。
19. Stage3 废弃运行参数已清理，`main.py --help` 不再暴露不会真实生效的 `--all-tags`、`--max-tags` 或 `--early-stop-n`。
20. Stage3 prompt v1 已静态接入并完成 8-CVE cost gate：`stage3_verdict_v0=legacy_navigation` 已标记为 deprecated baseline，`stage3_verdict_v1=target_tag_theorem_judge` 已成为默认主路径。
21. A/B 评估脚本已加入本地 fixture，并已修复 OpenCode session-wrapped tool-call 统计与 UNKNOWN/ERROR improved 分类；当前可比较每 tag 平均耗时、tool calls、完整 message JSON 字符量、probed tag accuracy、FP/FN/UNKNOWN、JSON parse failure、improved/regression cases。
22. Stage3 v1 已压缩 prompt 并修复目标 repo 定位问题：prompt 显式写入 repository path，并要求使用 `git -C <repo_path>`，避免 OpenCode 在 VulnVersion 工程根目录误查 tag。

## Not Yet Improved

1. 本轮不进行全量 OpenCode CVE 端到端 smoke run。
2. trace 已接到每次 `run_json` 并支持调用级 artifacts，但还没有真实 CVE live trace 样本。
3. memory/skills/prompt templates 仍未实际注入；当前只生成候选与审计/gate 结果。
4. Codex/Claude 没有接入，也不能作为实验结果声明。
5. ReplayRuntime 仅完成本地 artifact replay，尚未对历史 CVE trace 做覆盖率和一致性验证。
6. Prompt templates 尚未替代当前 Python prompt builder。
7. Harness mode 只记录配置，不驱动 memory/skills/replay 行为。
8. Self-evolution case pack 已可执行 leakage/promotion blocking gate，但仍未通过 ReplayRuntime batch replay 和小样本 OpenCode 验证，不能作为 memory/skills 注入依据。
9. `cwe-skills` learned overlay 仅有目录和规则，不存在 verified learned rule。
10. Stage3 长耗时问题尚未由本次清理解决；后续应设计真实 probe budget / plan budget，而不是恢复已删除兼容参数。
11. Stage3 prompt v1 已完成 8-CVE Stage3-only OpenCode cost gate，但尚未完成正式 BaseDataOrder 子集或全量验证。
12. v0 暂不物理删除，只作为 deprecated baseline 保留到 v1 通过更大样本稳定性验证；当前 v1 仍有 1 个 timeout 需要单独归因。

## Next Milestones

| 优先级 | 目标 | 验收标准 |
|---|---|---|
| P0 | OpenCode adapter hardening | 已完成非 CVE live probe：`agent_trace.jsonl`、`agent_runtime.json` 可真实落盘 |
| P0 | Stage-level smoke run | 暂不跑全量 CVE；待 Step3 稳定后，分别对 Stage1/Stage2/Stage3 做小样本分阶段 smoke |
| P1 | AgentTask 小样本验证 | Stage1/2/3 已静态迁移；下一步分别做非全量、小样本路径验证 |
| P1 | ReplayRuntime v1 coverage | 已能本地回放单条 artifact；下一步统计历史 `agent_calls/index.jsonl` 覆盖率和 miss 原因 |
| P1 | Case pack replay gate | 对 `Result_agent_enhance_cases/stage3_agent_judge_failures_v0/` 执行 ReplayRuntime 覆盖率统计，输出 unexplained miss 原因 |
| P1 | Memory gate evidence fill | 为 `stage3_agent_judge_failures_v0` 生成 replay summary、小样本 summary、improved/regression/unchanged reports；保持泄漏内容 blocked |
| P1 | Stage3 prompt v0/v1 A/B | 已完成 8-CVE/40-tag Stage3-only cost gate，v1 为 10 improved / 0 regression；下一步对 `linux/CVE-2022-0171/v5.12` timeout 做 case attribution，并在正式 BaseDataOrder 子集上验证默认 v1 |
| P2 | Memory read-only injection | 只有 case pack + ReplayRuntime + 小样本验证通过后，才实现只读 retrieval bundle 和审计；不把 memory hint 当作 verdict evidence |
| P2 | Skill selector v1 | 只允许 `verified` skill 注入，并记录 selected/suppressed skills；`.opencode/skills` 仍只属于 OpenCode native |
| P3 | Codex/Claude adapter | 在 OpenCode 跑稳后，再实现各自 CLI/SDK runtime |

## Quantification Rules

每个改进必须绑定证据：

```text
design_doc -> source_scaffold -> static_check -> smoke_run -> batch_eval
```

不能把“有目录/有类”称为“已完成接入”。当前状态术语：

- `reserved only`: 只有占位，不能用于实验。
- `schema scaffold only`: 有 schema，但主流程未用。
- `static integrated`: 主流程静态引用，compile/import 通过。
- `live validated`: 至少一个真实 CVE 跑通。
- `batch validated`: 有批量指标和失败分析。
