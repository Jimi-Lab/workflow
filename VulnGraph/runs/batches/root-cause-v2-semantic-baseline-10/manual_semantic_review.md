# Manual Semantic Review: root-cause-v2-semantic-baseline-10

Scope: 10 CVEs in `root-cause-v2-semantic-baseline-10`.

Inputs checked:

- `compact_review_packet.json`
- Per-CVE `root_cause_packet.json`
- Per-CVE `evidence_trace.json`
- Per-CVE `parsed_output.json` or `raw_response.txt`
- Per-CVE `contract_lint.json`
- Per-CVE `ingestion_result.json`

Constraints followed:

- No original packet, evidence, parsed, raw, lint, or ingestion files were modified.
- OpenCode was not rerun.
- No affected-version, BIC, or SZZ judgment was made.
- `evidence_link_precise` was judged only from code-supporting patch evidence such as git show unified / patch_diff. `git log --follow` and stat evidence were not used alone for code predicates.

Label convention:

- Label values are `0`, `1`, `N/A`, or `UNKNOWN`; this file uses only `0` and `1`.
- `severity=1` means the semantic/structural issue is blocking or major for the case.
- `severity=0` means the case is acceptable overall or only has non-blocking caveats.

## Summary Metrics

Accepted cases are cases with `ingested_raw` status: all except `CVE-2020-19667` and `CVE-2022-0171`.

- accepted cases semantic correct rate: 6/8 = 75.00%
- overall correct rate among all 10: 6/10 = 60.00%
- anchor_hunk_precision: 8/10 = 80.00%
- evidence_link_precision: 4/10 = 40.00%
- unsupported_inference_rate: 6/10 = 60.00%
- multi_fix_semantic_coverage: 1/2 = 50.00%

Multi-fix semantic coverage details:

- Covered: `CVE-2020-11984` includes both httpd fix commits and semantically covers the type widening and explicit `APR_UINT16_MAX` guard.
- Not covered: `CVE-2020-14212` includes both FFmpeg fix commits structurally, but anchors only cover the `dnn_backend_native.c` top-level operand hunk and miss layer loader operand-index guard hunks.

## Label Table

| CVE | mech | vuln_pred | fix_pred | file | func | hunk | evidence | unsupported | fix_set | minimal | overall | severity |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| CVE-2020-14212 | 1 | 0 | 0 | 1 | 1 | 0 | 0 | 1 | 1 | 0 | 0 | 1 |
| CVE-2020-19667 | 1 | 1 | 1 | 1 | 0 | 1 | 0 | 0 | 0 | 1 | 0 | 1 |
| CVE-2020-8231 | 1 | 1 | 1 | 1 | 1 | 1 | 0 | 0 | 1 | 0 | 1 | 0 |
| CVE-2020-11984 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 0 |
| CVE-2022-0171 | 1 | 1 | 1 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| CVE-2022-0286 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 0 | 1 | 1 | 1 | 0 |
| CVE-2020-15389 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 0 |
| CVE-2020-1967 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 0 | 1 | 0 |
| CVE-2020-11869 | 1 | 0 | 0 | 1 | 1 | 1 | 0 | 1 | 1 | 0 | 0 | 1 |
| CVE-2020-13164 | 1 | 1 | 1 | 1 | 1 | 1 | 0 | 1 | 1 | 0 | 1 | 0 |

## Per-CVE Review Notes

### CVE-2020-14212

Status: `ingested_raw`, contract OK.

The core FFmpeg DNN mechanism is right: operand indexes loaded from the model must be checked against `network->operands_num` to avoid out-of-bounds access. Patch evidence shows two fix commits and many hunks, including:

- `dnn_backend_native.c`: pass `network->operands_num` into `pf_load`.
- `dnn_backend_native.c`: check top-level `operand_index >= network->operands_num`.
- Layer loaders such as conv2d, depth2space, mathbinary, mathunary, maximum, and pad: validate input and output operand indexes against `operands_num`.

The parsed output anchors only `libavfilter/dnn/dnn_backend_native.c:2` for both fix commits. It does not anchor the layer loader guard hunks even though the hypothesis says the issue affects various `dnn_load_layer_*` functions. This is structural fix-set inclusion but not semantic multi-fix/hunk coverage.

Judgment: core mechanism correct, but vulnerable/fix predicates and hunk coverage are incomplete. Overall root cause label is 0.

### CVE-2020-19667

Status: `rejected`.

Failure class: function binding / structural gate. `contract_lint.json` reports that the CodeAnchor names `ReadXPMImage` but lacks `function_id`; the anchor, predicates, and hypothesis are then rejected.

Patch evidence in `coders/xpm.c` adds:

- `memset(target, 0, sizeof(target))`
- `memset(symbolic, 0, sizeof(symbolic))`

Semantic plausibility: the model's target/symbolic buffer initialization explanation is broadly plausible and points to the right file and hunk. However, because the anchor is structurally rejected, `overall_root_cause_correct=0`.

### CVE-2020-8231

Status: `ingested_raw`, contract OK.

The curl UAF mechanism is correct. The old `struct connectdata *lastconnect` could become stale after the connection lifecycle changed; the patch replaces it with `lastconnect_id` and looks up a still-live connection in the connection cache before returning it from `Curl_getconnectinfo`.

Precise supporting hunks include:

- `lib/urldata.h`: `lastconnect` pointer replaced by `lastconnect_id`.
- `lib/connect.c`: `Curl_getconnectinfo` validates `lastconnect_id` through conncache lookup and resets to `-1` if not found.
- `lib/multi.c`: updates/removes connection lifecycle state and close-connect-only checks.

The parsed anchors include only `lib/urldata.h` and `lib/connect.c`. They omit the `multi.c` lifecycle hunks that explain how the dangling pointer arises when handles/connections are removed. Therefore the root cause is correct overall, but evidence link precision and minimality are not.

### CVE-2020-11984

Status: `ingested_raw`, contract OK.

The httpd `mod_proxy_uwsgi` mechanism is supported. Both fix commits make the same semantic change:

- `pktsize`, `keylen`, and `vallen` are widened from `apr_uint16_t` to `apr_size_t`.
- `pktsize = headerlen - 4` is computed before serialization.
- `if (pktsize > APR_UINT16_MAX)` logs and returns `HTTP_INTERNAL_SERVER_ERROR`.
- The old later assignment of `pktsize` is removed.

The true blocking condition is the explicit `APR_UINT16_MAX` guard, with the type widening needed so oversized values can be represented before checking. The model is correct overall but has two caveats: it conflates CHANGES text saying "16K" with the actual `APR_UINT16_MAX` / 65535 guard, and it overstates "Buffer Overflow (potential)" beyond what the hunk directly proves.

### CVE-2022-0171

Status: `parse_error`.

Diagnosis: `schema_validation_missing_path`, not malformed/no JSON. `raw_response.txt` is fenced JSON. `parse_error.json` reports:

- `code_anchors.1.path` missing
- `code_anchors.2.path` missing
- `code_anchors.3.path` missing
- `code_anchors.4.path` missing

Only `anchor-1` has a `path`; anchors 2 through 5 use `file_id`, `function_id`, and `patch_hunk_id` but omit required `path`.

Semantic plausibility: high. The raw response describes KVM SEV cache incoherency when encrypted guest memory is reclaimed or unmapped. Patch evidence supports `on_unlock`, `kvm_arch_guest_memory_reclaimed`, `sev_guest_memory_reclaimed`, and `wbinvd_on_all_cpus()` wiring. Commit message directly describes stale confidential cachelines and host crash/data corruption risk. Because schema validation fails, `overall_root_cause_correct=0`.

### CVE-2022-0286

Status: `ingested_raw`, contract OK.

The Linux bonding root cause is exact. In `drivers/net/bonding/bond_main.c::bond_ipsec_add_sa`, old code assigned:

- `slave = rcu_dereference(bond->curr_active_slave);`
- then used `slave->dev` without checking `slave`.

The patch adds:

- `if (!slave) { rcu_read_unlock(); return -ENODEV; }`

The model correctly states the vulnerable predicate, the fix predicate, and the anchor hunk. No unsupported inference was found.

### CVE-2020-15389

Status: `ingested_raw`, contract OK.

The openjpeg mechanism is supported. Patch evidence moves the following variable initialization from function scope into the per-image loop in `opj_decompress.c::main`:

- `opj_image_t *image = NULL`
- `opj_stream_t *l_stream = NULL`
- `opj_codec_t *l_codec = NULL`
- `opj_codestream_index_t *cstr_index = NULL`

This prevents stale freed pointers from a previous image iteration or error path from being cleaned up again. The commit message supports double-free on a directory with a mix of valid and invalid images.

Caveat: the model sometimes says "use-after-free or double-free". Patch and commit evidence directly support double-free; UAF is not directly established by the hunks. Overall root cause remains correct.

### CVE-2020-1967

Status: `ingested_raw`, contract OK.

The OpenSSL NULL dereference is supported. In `ssl/t1_lib.c::tls1_check_sig_alg`, the patch changes:

- `if (sig_nid == sigalg->sigandhash)`

to:

- `if (sigalg != NULL && sig_nid == sigalg->sigandhash)`

The commit message explains that unsupported client `signature_algorithms_cert` values can make lookup return NULL, and old code unconditionally dereferenced the result. The model is correct overall.

Caveats: the model generalizes the NULL source to `tls1_lookup_sigalg` or `s->shared_sigalgs[i]`, but wrapper evidence directly supports unsupported client values through lookup. It also omits the TLS 1.3 `SSL_check_chain()` callback trigger context. This is a minimality issue, not a core mechanism failure.

### CVE-2020-11869

Status: `ingested_raw`, contract OK.

The QEMU `ati_2d_blt` model is overbroad. Patch evidence supports:

- `bpp` zero check.
- `dst_stride` zero check.
- `src_stride` zero check.
- signed-to-unsigned changes for source and destination coordinates.
- conditional destination coordinate update based on blit direction flags.

However, the model turns all patch changes into root cause. The commit message only says malicious guest values can make pixman functions receive crash-inducing parameters and that more checks are added. Hunk evidence does not directly prove division by zero, broad out-of-bounds access, or integer overflow/underflow as the precise trigger. The coordinate update hunks are patch behavior, but wrapper evidence does not prove them as the vulnerability trigger.

Judgment: mechanism direction is partly right, but predicate correctness, evidence link precision, minimality, and overall root cause fail under strict semantic review.

### CVE-2020-13164

Status: `ingested_raw`, contract OK.

The Wireshark NFS mechanism is correct. Patch evidence adds:

- `NFS_MAX_FS_DEPTH 100`
- `packet_info *pinfo` propagation into `nfs_full_name_snoop`
- per-packet `fs_depth` tracking with `p_get_proto_data` and `p_add_proto_data`
- early return and `nns->fs_cycle = TRUE` when depth is too large
- expert warning for possible file system cycle

The commit message says "Add filesystem cycle detection" and "Detect cycles and large depths when snooping full names".

Caveats: the patch does not implement a visited set or exact ancestor tracking. It is a recursion-depth threshold that reports a possible cycle. Also, the eight anchors include include directives and expert field declaration/registration hunks, which are plumbing/UI rather than minimal root-cause evidence. Overall root cause is still correct.
