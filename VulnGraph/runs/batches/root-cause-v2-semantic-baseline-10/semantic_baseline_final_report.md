# 10-CVE Root Cause Semantic Baseline Final Report

## 实验范围

本报告冻结 `root-cause-v2-semantic-baseline-10` 的 10-CVE Root Cause Agent semantic baseline。

范围仅限 Root Cause Agent 输出的结构与语义审核：

- 未运行 Judge。
- 未运行 SZZ。
- 未进入 BIC 判断。
- 未进行 affected-version 判断。
- 未重跑 OpenCode。
- 未修改任何 per-CVE 原始 agent 输出文件，包括 `root_cause_packet.json`、`evidence_trace.json`、`parsed_output.json`、`raw_response.txt`、`contract_lint.json`、`ingestion_result.json`。

本次新增的冻结产物：

- `manual_semantic_labels.csv`
- `manual_semantic_labels_normalized.csv`
- `manual_semantic_review.md`
- `manual_metrics_summary.json`
- `semantic_baseline_final_report.md`

## 结构结果

本轮 baseline 使用真实 OpenCode 调用产物：

- 10 real OpenCode invocations
- 8 `ingested_raw`
- 1 structural rejected
- 1 parse/schema validation error

结构失败分类：

- `CVE-2020-19667`: `structural_gate/function_binding`
  - CodeAnchor 输出了函数名 `ReadXPMImage`，但缺少 packet 中的 `function_id`，导致 anchor/predicate/hypothesis gate 拒绝。
- `CVE-2022-0171`: `schema_validation_missing_path`
  - `raw_response.txt` 是 fenced JSON，不是无 JSON 输出。
  - 失败原因是 `code_anchors.1.path` 到 `code_anchors.4.path` 缺失。

## 语义结果

人工语义审核口径：

- `overall_root_cause_correct=1` 表示模型 root cause 由 patch hunk 和 wrapper git unified diff 真实支撑。
- 对 `status=rejected` 或 `parse_error` 的 case，`overall_root_cause_correct` 原则上为 0；可在 notes 中单独记录 semantic plausibility。
- `evidence_link_precise` 只接受 patch_diff / git show unified 等能支撑代码谓词的 evidence；`git log --follow` 和 stat 只能作为上下文。

结果：

- all-case semantic correctness: 6/10 = 0.60
- accepted-only semantic correctness: 6/8 = 0.75
- all-case anchor_hunk_precision: 8/10 = 0.80
- accepted-only anchor_hunk_precision: 7/8 = 0.875
- all-case evidence_link_precision: 4/10 = 0.40
- accepted-only evidence_link_precision: 4/8 = 0.50
- all-case unsupported_inference_rate: 6/10 = 0.60
- accepted-only unsupported_inference_rate: 6/8 = 0.75

Overall correct cases:

- `CVE-2020-8231`
- `CVE-2020-11984`
- `CVE-2022-0286`
- `CVE-2020-15389`
- `CVE-2020-1967`
- `CVE-2020-13164`

Overall failed cases:

- `CVE-2020-14212`
- `CVE-2020-19667`
- `CVE-2022-0171`
- `CVE-2020-11869`

## Multi-Fix 结果

本报告明确区分两个口径：

1. structural fix-set coverage
   - 原始 structural / multi-fix gate 口径。
   - 判断 fix commits 是否都被结构上纳入 fix_set / anchors。

2. semantic fix-set coverage
   - 人工语义覆盖口径。
   - 判断每个 fix commit 的关键修复语义是否都被 predicates 和 anchors 覆盖，而不是只出现 commit ID 或无关 hunk。

结果：

- structural multi-fix coverage: 2/2 = 1.00
- semantic multi-fix coverage: 1/2 = 0.50

两个 multi-fix case 的区别：

- `CVE-2020-14212`
  - Structural coverage = 1
  - Semantic coverage = 0
  - 两个 FFmpeg fix commits 都被结构上列入 fix_set。
  - 但模型 anchors 只覆盖 `dnn_backend_native.c` 顶层 `operand_index >= network->operands_num` hunk。
  - 关键 layer-loader operand-index guard hunks 没有被语义覆盖，例如 conv2d、depth2space、mathbinary、mathunary、maximum、pad 等 loader 中对 input/output operand index 的检查。

- `CVE-2020-11984`
  - Structural coverage = 1
  - Semantic coverage = 1
  - 两个 httpd fix commits 都被纳入并覆盖同一语义修复：`pktsize` 从 `apr_uint16_t` 扩展为 `apr_size_t`，并在序列化前增加 `pktsize > APR_UINT16_MAX` 的显式 guard。
  - Caveat 是模型把 CHANGES 中的 `16K` 表述和实际 `APR_UINT16_MAX` / 65535 guard 混在一起，并将 `Buffer Overflow (potential)` 写得偏强；但核心 fix-set 语义覆盖完整。

因此，`manual_semantic_labels.csv` 中旧字段 `fix_set_complete` 不再解释为 multi-fix semantic coverage。最终使用：

- `fix_set_structurally_complete`
- `fix_set_semantically_complete`

这两个 normalized 字段分别表示结构覆盖和语义覆盖。

## 主要失败类型

### Schema / Contract Adherence

Case: `CVE-2022-0171`

- `raw_response.txt` 是 fenced JSON。
- 失败不是无 JSON 输出。
- 真正原因是多个 code anchors 缺少 required `path` 字段。
- 缺失字段：
  - `code_anchors.1.path`
  - `code_anchors.2.path`
  - `code_anchors.3.path`
  - `code_anchors.4.path`

### Function Binding / Gate Rejection

Case: `CVE-2020-19667`

- Anchor 写了函数名 `ReadXPMImage`。
- 但没有复制 packet 中的 `function_id`。
- Gate 拒绝 anchor 后，相关 vulnerable predicate、fix predicate、hypothesis 也被拒绝。

### Incomplete Hunk Coverage

Case: `CVE-2020-14212`

- 模型识别出 FFmpeg DNN operand index validation 的正确机制。
- 但 hunk coverage 停留在 `dnn_backend_native.c` 顶层 operand hunk。
- 没有覆盖 hypothesis 自己提到的 `dnn_load_layer_*` loader guards。

### Overbroad Semantic Inference

Case: `CVE-2020-11869`

- QEMU ATI VGA `ati_2d_blt` 的 patch 同时包含坐标 unsigned 化、`bpp` 检查、`dst_stride/src_stride` 检查、坐标更新逻辑修正。
- 模型把所有 patch 修复点都等价写成 root cause。
- `division by zero`、泛化 OOB、泛化 integer overflow/underflow、以及坐标更新逻辑作为漏洞触发条件，都没有被 patch_diff 直接证明到相同强度。

### Evidence Link Imprecision

多个 case 存在 evidence link 不精确：

- `CVE-2020-14212`: 漏掉 layer-loader guard hunks。
- `CVE-2020-8231`: 漏掉 `multi.c` 生命周期 hunks，影响 stale connection pointer 触发链完整性。
- `CVE-2020-11869`: predicates 超出 hunk 直接支撑范围。
- `CVE-2020-13164`: anchors 包含 include、expert field declaration/registration 等 plumbing hunk，不是最小 root-cause evidence。

## 下一阶段 VulnGraph 优化方向

1. 强制 `code_anchors[*].path`。
   - 缺少 `path` 应在生成侧或 schema repair 阶段直接阻断，避免 fenced JSON 因字段缺失进入 parse_error。

2. 如果输出 `function` / `function_name`，必须复制 packet 中的 `function_id`；否则不要输出函数名。
   - 这可以避免 `CVE-2020-19667` 这类 function binding failure。

3. Predicate 只能由 `patch_diff` / `git show unified` 支撑。
   - `git log --follow` 和 stat 只能作为上下文，不得单独支撑 code predicate。

4. 对 hypothesis 中提到的每个关键函数 / loader，必须 anchor 到对应 hunk。
   - 例如 `CVE-2020-14212` 中，若 hypothesis 写到多个 `dnn_load_layer_*`，就必须 anchor 对应 layer loader operand-index guard hunk。

5. 禁止把 patch 未直接证明的现象写成 root cause。
   - 例如 potential buffer overflow、泛化 OOB、泛化 cycle detection、泛化 division-by-zero 等，必须有 hunk 级证据或降级为 caveat / possible consequence。

## 结论

这次 10-CVE Root Cause Agent semantic baseline 已冻结。

冻结后的关键产物是：

- `manual_semantic_labels_normalized.csv`
- `manual_metrics_summary.json`
- `semantic_baseline_final_report.md`

该 baseline 口径明确区分结构成功、schema/contract 失败、patch evidence 支撑的语义正确性、以及 multi-fix 的 structural coverage 与 semantic coverage。后续优化 prompt、schema 或 gate 时，应以本 baseline 作为优化前对照，不覆盖旧指标文件，也不改动 per-CVE 原始 agent 输出。
