# Repo Tag Feature Guide for Step3 Optimization

This file summarizes the real tag characteristics of the 9 target repos in
`workflow/VulnVersion/DataSet/BaseDataSet.json`, so Step3 can be optimized per
repo instead of using one generic strategy.

The numbers below are derived from the current local repos and the dataset.

---

## Quick View

| Repo            | Repo Tags | Unique GT Tags | Main Tag Family                       | GT Line Shape                      | Multi-fix Branching | Step3 Meaning                       |
| --------------- | --------: | -------------: | ------------------------------------- | ---------------------------------- | ------------------: | ----------------------------------- |
| `curl`        |       229 |            228 | `curl-7_75_0`                       | almost pure single line            |                   0 | single-line optimization            |
| `ImageMagick` |       402 |            361 | `7.0.10-10`                         | mostly `7.0`, small `7.1`      |                   3 | single-line / two-line optimization |
| `FFmpeg`      |       415 |            368 | `n4.2.3`                            | many release lines                 |                  44 | strong branch-family handling       |
| `httpd`       |       306 |            187 | `2.4.49`                            | `2.4`, `2.2`, `2.3`, `2.0` |                  10 | backport-aware line handling        |
| `openssl`     |       425 |            152 | `OpenSSL_1_1_1w`, `openssl-3.0.4` | many naming families               |                   0 | strong line-family handling         |
| `qemu`        |       445 |            138 | `v5.2.0`                            | many stable lines                  |                   7 | stable-branch-aware handling        |
| `wireshark`   |      1096 |            576 | `v3.0.7`, `wireshark-3.0.7`       | many mirrored lines                |                   3 | dual-family naming handling         |
| `openjpeg`    |        26 |             17 | `v2.3.0`, `version.2.0`           | small but legacy-heavy             |                   2 | legacy-line retention               |
| `linux`       |       922 |             98 | `v5.15`, `v6.1`                   | huge stable/LTS space              |                   0 | stable-line + caching/indexing      |

---

## Why Tag Features Matter

Step3 has two different subproblems:

1. `tag_plan.json` must **cover** dataset `affected_version`
2. The execution phase must verify tags **cheaply**

The best optimization depends on tag structure:

- if a repo is effectively one long mainline, optimize with boundary search
- if a repo has many release lines, optimize with line-aware planning and line-local stop rules
- if a repo has multiple naming families, unify names before planning
- if a repo has legacy/EOL lines in GT, do not prune old lines too early

---

## Curl Example (Visual)

`curl` is the cleanest example because it is almost a pure single-line release history.

### What curl tags look like

Typical real tags:

```text
curl-8_10_1
curl-8_10_0
curl-8_9_1
curl-8_9_0
...
curl-7_75_0
curl-7_74_0
...
curl-7_1
curl-6_5
...
```

The key property is:

- tags are basically one chronological release chain
- there is no strong evidence of parallel long-lived branch families in the dataset
- `fixing_commits` for curl CVEs do **not** usually appear as multi-commit branch families

### How Step3 should think about curl

Current mental model:

```text
single release line

newer ------------------------------------------------------------> older
fixed tags | NOT_AFFECTED zone | boundary | AFFECTED zone
```

So curl is not a "many-line planning" problem.
It is a **single-line boundary finding** problem.

### Visual intuition for one curl CVE

Suppose a CVE is fixed at `curl-8_1_0`.

```text
curl-8_10_1  curl-8_10_0  curl-8_9_1 ... curl-8_1_1  curl-8_1_0 | curl-8_0_1  curl-8_0_0 ... curl-7_75_0 ...
     N             N            N             N          N       |      A          A            A

Legend:
N = NOT_AFFECTED
A = AFFECTED
```

The optimization implication is obvious:

- do **not** verify all 150+ tags linearly
- find the boundary between `NOT_AFFECTED` and `AFFECTED`

### Best Step3 strategy for curl

```text
tag_plan stage:
  keep coverage high (single line is easy)

execution stage:
  1. probe newest tag
  2. probe oldest tag
  3. if mixed, binary search for boundary
  4. verify only a thin window around the boundary
```

That is why curl should use a **dedicated single-line strategy**.

---

## Repo-by-Repo Tag Features and Optimization Meaning

### 1. `curl`

Observed features:

- repo tags: `229`
- unique GT tags: `228`
- dominant prefix: `curl-*`
- GT lines: effectively just `main`
- multi-fix groups: `0`

Interpretation:

- this is almost the ideal single-line repo
- if Step3 is expensive on curl, the problem is not planning ambiguity, it is verification overkill

Best optimization:

- single-line boundary search
- aggressive line-local stop
- no need for multi-line heuristics

### 2. `ImageMagick`

Observed features:

- repo tags: `402`
- unique GT tags: `361`
- dominant naming: `7.0.10-10`
- GT lines are heavily dominated by `7.0`, with a smaller `7.1`

Interpretation:

- mostly a single-line problem, with a light secondary line
- current Step3 over-pays because it keeps huge `7.0` pre-fix prefixes

Best optimization:

- treat `7.0` as the main line
- use interval/boundary search inside `7.0`
- treat `7.1` as a secondary line, usually much smaller

### 3. `FFmpeg`

Observed features:

- repo tags: `415`
- unique GT tags: `368`
- dominant naming: `n*`
- GT is spread across many lines: `3.2`, `2.8`, `3.4`, `4.1`, `2.2`, `3.0`, `4.2`, `3.1`, `3.3`, `2.4`, ...
- multi-fix groups: `44`

Interpretation:

- FFmpeg is a **true branch-family repo**
- many CVEs are fixed separately on master + several release branches
- the main difficulty is not naming; it is branch-family-aware older-line retention

Best optimization:

- use `fixing_commits` family as a first-class planning signal
- map those fixes to release lines
- keep adjacent older lines conservatively
- then do line-local stop / boundary search per line

### 4. `httpd`

Observed features:

- repo tags: `306`
- unique GT tags: `187`
- dominant release tags: plain `x.y.z`
- GT lines: `2.4`, `2.0`, `2.2`, `2.3`, `2.1`, `1.3`
- multi-fix groups: `10`

Interpretation:

- httpd is strongly backport-oriented
- `2.4` is important, but `2.3` / `2.2` / `2.0` matter too
- current Step3 usually has to choose between missing old lines or paying too much

Best optimization:

- backport-aware line frontier modeling
- preserve key old lines, especially when fix families imply them
- line-local stop inside `2.4` should be stronger than current linear scan

### 5. `openssl`

Observed features:

- repo tags: `425`
- unique GT tags: `152`
- several naming families:
  - `OpenSSL_1_1_1*`
  - `OpenSSL_1_0_2*`
  - `openssl-3.0.*`
  - `OpenSSL-fips-*`
  - others
- GT lines: `1.1.1`, `1.0.2`, `3.0`, `1.1.0`, `3.1`, `1.0.1`, `fips-2.0`, ...

Interpretation:

- openssl is not just a many-line repo
- it is a **many-family + many-line repo**
- naming family itself is part of the planning semantics

Best optimization:

- explicit family-aware line grouping
- do not mix `OpenSSL_1_1_1*` with `openssl-3.0.*`
- execution-stage stop should happen inside each family-line separately

### 6. `qemu`

Observed features:

- repo tags: `445`
- unique GT tags: `138`
- dominant naming: `v*`
- GT lines span many stable lines: `2.1`, `1.5`, `3.1`, `2.6`, `2.10`, `1.6`, `1.7`, `2.0`, `2.11`, `2.5`, ...
- multi-fix groups: `7`

Interpretation:

- qemu is a classic stable-branch repo
- many older stable lines matter in GT
- if Step3 prunes old stable lines too aggressively, it loses coverage

Best optimization:

- stable-branch-aware planning
- line-local verification with representative probing first
- only after that do boundary search inside likely affected stable lines

### 7. `wireshark`

Observed features:

- repo tags: `1096`
- unique GT tags: `576`
- two large naming families:
  - `v*`
  - `wireshark-*`
- GT lines spread across many families: `2.6`, `3.2`, `2.4`, `3.0`, `2.2`, `2.0`, `3.4`, `1.12`, `1.10`, `1.8`, ...

Interpretation:

- wireshark is the hardest naming problem among the 9 repos
- the same semantic release line often appears in two naming forms
- current planning must treat these as one line semantically, but execution should avoid double-paying too much

Best optimization:

- dual-family naming normalization
- canonical representative tags per line in execution phase
- only expand to the mirrored family when necessary

### 8. `openjpeg`

Observed features:

- repo tags: `26`
- unique GT tags: `17`
- mixed naming:
  - `v2.3.0`
  - `version.2.0`
- GT lines include many legacy versions: `2.1`, `2.3`, `2.0`, `1.5`, `2.2`, `1.2`, `1.4`, `1.3`, `1.1`, `1.0`
- multi-fix groups: `2`

Interpretation:

- openjpeg is small, but legacy-heavy
- the challenge is not scale, but preserving legacy lines

Best optimization:

- explicit legacy-line retention
- do not over-prune old `version.*` families
- cost optimization is secondary because the repo is small anyway

### 9. `linux`

Observed features:

- repo tags: `922`
- unique GT tags: `98`
- dominant naming: `v*`
- GT lines spread across many stable/LTS families: `2.6`, `5.16`, `5.15`, `5.17`, `5.14`, `5.18`, `5.13`, `5.19`, `5.12`, `5.11`, ...
- dataset contains `717` linux CVEs

Interpretation:

- linux is not just a normal multi-line repo; it is a huge stable/LTS ecosystem
- the main challenge is scale + stable line structure

Best optimization:

- stable-line-aware planning
- heavy caching/indexing
- execution should use representative probing first, not immediate linear scanning

---

## Practical Step3 Implications

Use this table when designing repo-specific Step3 phase-2 strategies.

| Repo            | Best Step3 Phase-2 Strategy                                   |
| --------------- | ------------------------------------------------------------- |
| `curl`        | single-line boundary search                                   |
| `ImageMagick` | main-line boundary search with small secondary-line handling  |
| `FFmpeg`      | branch-family-aware line probing + line-local boundary search |
| `httpd`       | backport-aware line probing + stronger line-local stop        |
| `openssl`     | family-line-separated verification                            |
| `qemu`        | stable-line representative probing first                      |
| `wireshark`   | dual-family canonical probing first                           |
| `openjpeg`    | legacy-line retention, then cheap full verification           |
| `linux`       | stable/LTS representative probing + caching                   |

---

## Files

- dataset: `workflow/VulnVersion/DataSet/BaseDataSet.json`
- step3 planning coverage summary: `workflow/VulnVersion/tests/step3_cve_versionCoverage/full_run_v2/readme.md`
- code:
  - `workflow/VulnVersion/vulnversion/stage3_verify/version_registry.py`
  - `workflow/VulnVersion/vulnversion/stage3_verify/plan_tags.py`
