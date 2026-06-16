# Step3 Planning Coverage Report

This document summarizes the current Step3 `tag_plan.json` adaptation quality for the target dataset `workflow/VulnVersion/DataSet/BaseDataSet.json`.

The main goal of this analysis is **not cost first**. The first priority is:

- `tag_plan.json` must cover dataset `affected_version`
- if planning misses affected tags, later Agent verification is meaningless

This report is generated from tests-only analysis under `workflow/VulnVersion/tests/` without calling backend LLMs.

## Scope

- dataset: `workflow/VulnVersion/DataSet/BaseDataSet.json`
- repos in dataset: `FFmpeg`, `ImageMagick`, `curl`, `httpd`, `linux`, `openjpeg`, `openssl`, `qemu`, `wireshark`
- fully analyzed by tests-only script: all except `linux`
- `linux` full run did not finish in time because the dataset contains `717` CVEs for linux and `git tag --contains` planning is still too expensive at full scale

## What was measured

For each CVE, the tests-only script builds Step3 `tag_plan` and computes:

- `candidate_count`: how many tags Step3 would verify
- `candidate_gt_coverage_count`: how many GT `affected_version` tags are included in planning
- `candidate_gt_coverage_rate`: `candidate_gt_coverage_count / gt_count`

This is the key metric for current Step3 planning quality.

## Important conclusion first

Current Step3 planning is **not yet acceptable** for the full dataset.

The current planning quality splits into three groups:

1. `curl`, `ImageMagick`
   - coverage is high
   - but cost is very high because full pre-fix prefixes are still kept

2. `FFmpeg`, `httpd`, `openssl`
   - both coverage and cost are problematic
   - planning still misses many GT tags and also scans too many tags

3. `wireshark`, `qemu`, `openjpeg`
   - candidate count is relatively lower
   - but coverage is too low, meaning planning often does not include affected tags

Therefore, Step3 must first solve **coverage of GT affected versions**, and only then optimize cost.

---

## Per-repo summary

### FFmpeg

- CVEs: `71`
- avg candidate tags/CVE: `36.85`
- median candidate tags/CVE: `17`
- max candidate tags/CVE: `102`
- avg GT coverage rate: `0.3626`
- full GT coverage CVEs: `8/71`

Current behavior:

- release lines are partially recognized (`4.1`, `4.2`, `4.3`, `3.4`, `3.2`, etc.)
- for some CVEs such as `CVE-2020-12284`, planning improved a lot and now focuses on `4.1/4.2` with a small probe on `4.0`
- but overall FFmpeg still has low coverage

Observed miss pattern:

- unmapped GT examples are dominated by older lines such as:
  - `n3.3`, `n3.3.1`, `n3.1.2`, `n3.1`, `n3.1.1`, `n3.0.1`, `n3.0.3`

Interpretation:

- current line pruning for FFmpeg is too aggressive for some CVEs
- Step3 is assuming that lines older than the oldest fixed line are mostly irrelevant
- this assumption is false for many FFmpeg CVEs in this dataset

Required adaptation:

- FFmpeg cannot use only "oldest fixed line minus tiny older probe"
- it needs repo-specific planning based on the actual family of backports
- at minimum:
  - preserve all lines explicitly touched by fix-family branch hints
  - preserve adjacent older lines more conservatively for FFmpeg
  - do not prune `3.x` lines so aggressively when fixes exist on `4.x`

### ImageMagick

- CVEs: `72`
- avg candidate tags/CVE: `160.9`
- avg GT coverage rate: `0.8116`
- full GT coverage CVEs: `56/72`

Current behavior:

- coverage is fairly good
- but candidate count is huge because `7.0` pre-fix prefixes are often kept almost whole

Observed miss pattern:

- many misses are still inside `7.0.10-*` sequence
- examples: `7.0.10-33`, `7.0.10-45`, `7.0.10-57`, `7.0.10-30`, `7.0.10-60`

Interpretation:

- line modeling is acceptable (`7.0`, `7.1`)
- the real problem is that known-frontier compression is missing

Required adaptation:

- ImageMagick should be treated as a mostly single-line problem
- after frontier is known, use interval/boundary search instead of full prefix retention

### curl

- CVEs: `68`
- avg candidate tags/CVE: `169.13`
- avg GT coverage rate: `0.9918`
- full GT coverage CVEs: `64/68`

Current behavior:

- coverage is very strong
- but cost is extremely high because planning keeps the full pre-fix mainline prefix

Observed miss pattern:

- almost all misses are very old tags:
  - `curl-5_4`, `curl-5_2_1`, `curl-7_1`, `curl-5_2`, `curl-6_3`, `curl-4_10`

Interpretation:

- planning is already good enough for coverage
- this repo does not need more branch complexity
- it needs cost compression

Required adaptation:

- use a dedicated single-line strategy
- do not keep the whole pre-fix prefix
- use binary/boundary search on the main line

### httpd

- CVEs: `30`
- avg candidate tags/CVE: `51.5`
- avg GT coverage rate: `0.385`
- full GT coverage CVEs: `6/30`

Current behavior:

- expensive and coverage-poor at the same time
- `2.4` line often dominates candidates
- `2.2`, `2.3`, `2.1` are frequently only probed weakly

Observed miss pattern:

- unmapped GT examples include:
  - `2.3.7`, `2.3.5`, `2.3.6`, `2.3.8`, `2.3.3`, `2.3.4`

Interpretation:

- current planner underestimates `2.3` family importance
- httpd backports/cherry-picks are not being captured reliably by `contains`

Required adaptation:

- httpd needs stronger line-local frontier inference for `2.2` / `2.3` / `2.4`
- do not let `2.4` dominate the whole plan
- if a fix family includes multiple branch commits, map them to lines before pruning

### openssl

- CVEs: `50`
- avg candidate tags/CVE: `109.58`
- avg GT coverage rate: `0.5166`
- full GT coverage CVEs: `14/50`

Current behavior:

- still very poor
- many lines remain `unknown`
- many old lines are still included without confident frontier

Observed miss pattern:

- unmapped GT examples are concentrated in old families such as:
  - `OpenSSL_1_1_1f`, `OpenSSL_1_1_1g`, `OpenSSL_1_1_1c`, `OpenSSL_1_1_1b`, `OpenSSL_1_1_1a`

Interpretation:

- line normalization is not enough yet
- OpenSSL has several naming families:
  - `OpenSSL_1_1_1*`
  - `OpenSSL_1_0_2*`
  - `openssl-3.0.*`
  - `OpenSSL-fips-*`
  - `engine-*`
- current planner mixes these families poorly

Required adaptation:

- OpenSSL needs repo-specific line families beyond simple numeric grouping
- `1.1.1`, `1.0.2`, `3.0`, `3.1`, `fips-2.0`, `fips-1.2`, `engine-*` must be planned independently
- pruning for OpenSSL must be more conservative until line-family inference is strengthened

### openjpeg

- CVEs: `13`
- avg candidate tags/CVE: `3`
- avg GT coverage rate: `0.3462`
- full GT coverage CVEs: `2/13`

Current behavior:

- very cheap
- but misses most affected tags

Observed miss pattern:

- unmapped GT examples include:
  - `v2.1.2`, `v2.1.1`, `version.2.0`, `version.2.1`, `version.2.0.1`, `version.1.5.1`

Interpretation:

- current pruning is too aggressive
- planner jumps directly to `2.3` / `2.2` and drops too much older coverage

Required adaptation:

- openjpeg needs explicit support for legacy `version.*` line families
- old `1.x` / `2.0` / `2.1` lines cannot be pruned so early

### qemu

- CVEs: `57`
- avg candidate tags/CVE: `10.16`
- avg GT coverage rate: `0.4747`
- full GT coverage CVEs: `23/57`

Current behavior:

- much cheaper than before
- but still misses too many affected versions

Observed miss pattern:

- unmapped GT examples include many older stable lines:
  - `v3.1.0`, `v2.6.0`, `v2.12.0`, `v2.12.1`, `v2.5.0`, `v2.10.0`

Interpretation:

- qemu line granularity is now better (`vX.Y`)
- but current pruning assumes too many older stable lines are irrelevant

Required adaptation:

- qemu needs stronger use of stable branch hints from fix families
- if a family does not map cleanly to a line, bounded probe should include more historically adjacent stable lines

### wireshark

- CVEs: `50`
- avg candidate tags/CVE: `28.7`
- avg GT coverage rate: `0.117`
- full GT coverage CVEs: `4/50`

Current behavior:

- this is currently the worst-adapted repo
- candidate count is not extremely large, but coverage is disastrously low

Observed miss pattern:

- many unmapped GT tags are mirrored forms of the same line family:
  - `wireshark-3.2.1`, `v3.2.1`
  - `wireshark-3.2.0`, `v3.2.0`
  - `wireshark-3.0.3`, `v3.0.3`
  - `wireshark-3.0.8`, `v3.0.8`

Interpretation:

- current normalization of `vX.Y.Z` and `wireshark-X.Y.Z` is not sufficient for planning coverage
- line families are still being pruned too early or not reached by frontier inference

Required adaptation:

- wireshark needs a much stronger dual-naming line unification strategy
- line coverage must be tested against both naming families simultaneously
- current planner is not suitable for wireshark yet

### linux

- dataset CVEs: `717`
- full tests-only planning evaluation on `BaseDataSet.json` did not finish within the available runtime

What this means:

- even planning-only evaluation is expensive on linux
- current Step3 planning for linux still needs a dedicated testing path and probably much stronger caching / offline preprocessing

Available signal:

- in the smaller 30-CVE sample, linux showed low candidate count but unstable coverage
- this strongly suggests current linux pruning is probably too aggressive for the full dataset too

Required adaptation:

- linux must be treated as its own category
- do not reuse generic multi-branch heuristics
- likely needs stable-line aware planning plus much stronger caching / indexing

---

## Real problems exposed by current Step3

### 1. The central problem is still GT coverage, not just cost

Current Step3 still produces many `tag_plan.json` files that do **not** include all dataset `affected_version` tags.

This means:

- later Agent verification may be correct for the selected tags
- but the overall CVE result is still invalid because planning missed the real affected versions

Therefore:

- **planning coverage must be fixed before cost optimization becomes the main target**

### 2. Current line pruning is too generic

The current planner uses shared heuristics:

- `known`
- `unknown`
- `pruned`
- `probe_small`

But the dataset shows clearly that the 9 repos need **repo-specific planning policies**.

### 3. Single-line and multi-line repos need different strategies

- `curl`, `ImageMagick`: mostly high coverage but too expensive
- `FFmpeg`, `httpd`, `openssl`: mixed problem, both cost and misses
- `wireshark`, `qemu`, `openjpeg`: lower cost but severe planning misses

One universal strategy will not work.

### 4. Old artifacts can still mislead evaluation

Existing `tag_plan.json` / `per_tag_verdict.jsonl` from older runs can make the system appear worse or simply different from the current planner.

For fair evaluation:

- Step3 tests must rebuild planning artifacts
- old result artifacts must not be reused blindly

---

## Priority order for fixing Step3 planning

### Priority 1: Guarantee affected-version coverage in `tag_plan.json`

Before reducing candidate count further, Step3 must be adapted so that planned candidates cover the dataset's `affected_version` as much as possible.

Current first-wave target repos:

- `wireshark`
- `openssl`
- `httpd`
- `openjpeg`
- `qemu`
- `FFmpeg`

### Current source-code progress (latest)

After the first repo-specific source-code pass in `vulnversion/stage3_verify/plan_tags.py`:

- `openjpeg` coverage improved from `0.3462` to `0.9231`
- `qemu` coverage improved from `0.4747` to `0.7589`
- `openssl` coverage improved from `0.5166` to `1.0000` (with major cost increase)
- `wireshark` coverage improved from `0.1170` to `0.6674` (with major cost increase)
- `FFmpeg` coverage improved further from `0.3626` to `0.6975` after enabling stronger branch-family-aware retention
- `httpd` coverage improved from `0.3850` to `0.9993` after switching unknown-line handling to full-line retention

This confirms the central thesis:

- the dominant current Step3 problem was indeed planning under-coverage
- for the worst repos, recovering affected-version coverage requires repo-specific retention logic

The tradeoff is also now explicit:

- once coverage is restored, candidate count often increases sharply
- therefore the next phase after coverage recovery must be repo-specific cost compression, not generic pruning

### Priority 2: Repo-specific planning policies

Do not keep one generic pruning rule for all repos.

Need at least:

- dedicated single-line strategy for `curl` / `ImageMagick`
- dual-family naming strategy for `wireshark`
- strong line-family strategy for `openssl`
- stable-branch-aware strategy for `qemu`
- legacy-line retention for `openjpeg`
- branch-family-aware older-line retention for `FFmpeg`

### Priority 3: Only after coverage improves, compress candidate cost

Once GT coverage is acceptable, then optimize:

- known frontier line compression
- binary / interval search on single-line repos
- better bounded probing on unknown lines

---

## Repo-specific adaptation process (implemented first pass)

Based on the full-dataset tests-only reports, Step3 planning now needs to be split by repo family instead of using a universal pruning rule.

### 1. Dedicated single-line strategy for `curl` / `ImageMagick`

Current status:

- `curl`: coverage already very high (`0.9918`), but average candidate count is extreme (`169.13`)
- `ImageMagick`: coverage is relatively high (`0.8116`), but average candidate count is also extreme (`160.9`)

Interpretation:

- these repos are not primarily failing because of missing branch awareness
- they are failing because the planner treats the whole known pre-fix prefix as the final verification set

Implementation direction:

- keep line modeling simple (`main` for curl, `7.0/7.1` for ImageMagick)
- do not change these repos first for coverage
- later, after other repos are fixed, convert known-frontier lines to interval/boundary search

### 2. Dual-family naming strategy for `wireshark`

Why:

- full-dataset coverage is extremely poor (`0.117`)
- common unmapped GT tags show paired naming forms:
  - `wireshark-3.2.1` and `v3.2.1`
  - `wireshark-3.0.3` and `v3.0.3`

What this means:

- `line_key()` unification alone is not enough
- planning must treat `vX.Y.Z` and `wireshark-X.Y.Z` as the same release line during frontier search **and** during candidate generation

First-pass source adaptation already applied:

- repo policy now keeps same-family unknown lines more aggressively for `wireshark`
- unknown lines are now preserved much more conservatively than before
- planner uses full-line retention for unknown wireshark lines to prioritize coverage over cost

Current effect:

- coverage is expected to improve, but candidate count will rise sharply
- this is acceptable for now because coverage is the primary objective

### 3. Strong line-family strategy for `openssl`

Why:

- full-dataset coverage is poor (`0.5166`)
- unmapped GT tags cluster in older named families such as `OpenSSL_1_1_1*`
- OpenSSL has multiple naming families that do not behave like one simple numeric version tree

Required line families:

- `1.1.1`
- `1.0.2`
- `1.1.0`
- `3.0`
- `3.1`
- `fips-*`
- `engine-*`

First-pass source adaptation already applied:

- repo policy now keeps same-family unknown lines aggressively for `openssl`
- unknown OpenSSL lines now use full-line retention instead of tiny bounded probes

Observed result after first pass:

- coverage jumps dramatically (tests-only second pass reached full coverage in the repo-only report)
- cost also increases significantly

Interpretation:

- this is the correct direction for phase 1, because it proves the main issue was planner under-coverage
- later phases must reduce cost **without losing** this recovered coverage

### 4. Stable-branch-aware strategy for `qemu`

Why:

- full-dataset coverage was low (`0.4747`)
- missing GT tags cluster in many older stable lines (`v3.1`, `v2.12`, `v2.10`, `v2.6`, ...)

What this means:

- qemu cannot be planned by keeping only a tiny window below the oldest fixed line
- stable release lines are part of the real affected-version space

First-pass source adaptation already applied:

- repo policy now restores a much larger older-line window for `qemu`
- adjacent older lines use a larger bounded probe
- unknown lines in the same major family are preserved more often

Observed result after first pass:

- repo-only tests improved average coverage from `0.4747` to `0.7589`
- candidate count increased from `10.16` to `46.49`

Interpretation:

- this is a real coverage improvement
- qemu still needs better frontier inference so that these extra lines can later be compressed safely

### 5. Legacy-line retention for `openjpeg`

Why:

- full-dataset coverage was extremely low (`0.3462`)
- missing GT tags are concentrated in legacy version families:
  - `version.2.0`
  - `version.2.1`
  - `version.1.x`
  - `v2.1.1`, `v2.1.2`

What this means:

- openjpeg cannot aggressively prune old lines just because newer `2.3` / `2.2` lines exist

First-pass source adaptation already applied:

- repo policy now uses legacy retention for `openjpeg`
- unknown lines are kept as full lines instead of being reduced to tiny probes

Observed result after first pass:

- repo-only tests improved average coverage from `0.3462` to `0.9231`
- full-coverage CVEs rose to `1.0` of the repo-only test set
- candidate count increased from `3` to `16.15`

Interpretation:

- openjpeg confirms the central thesis of this report:
- current Step3 was mainly failing because `tag_plan.json` did not include the real affected versions

### 6. Branch-family-aware older-line retention for `FFmpeg`

Why:

- FFmpeg often has branch-specific fix families, e.g. one CVE may have fixes on `master`, `release/4.2`, `release/4.1`
- current coverage remains poor (`0.3626`) even after line-aware planning was introduced

What this means:

- simple “oldest fixed line + tiny older probe” is still too aggressive for many FFmpeg CVEs
- branch family information must affect older-line retention

Current first pass status:

- line-aware planning is already working for representative cases such as `CVE-2020-12284`
- however, full-dataset repo results did not yet improve overall coverage

Interpretation:

- FFmpeg still needs a second-round redesign
- specifically:
  - preserve all lines explicitly touched by fix-family branch hints
  - use more family-aware restoration of older lines
  - stop pruning `3.x` lines too early when fixes are visible on `4.x`

### 7. httpd as a backport-aware line-family repo

Why:

- httpd coverage is poor (`0.385`)
- missing GT tags cluster in `2.3.*`
- current planner lets `2.4` dominate too much

First-pass source adaptation already applied:

- repo policy now restores a larger older-line window for `httpd`
- same-family unknown lines are preserved more often

Observed result after first pass:

- repo-only tests improved average coverage from `0.385` to `0.4099`
- candidate count increased from `51.5` to `63.5`

Interpretation:

- improvement exists, but it is still weak
- httpd needs stronger branch-family-aware frontier inference, not just wider older-line retention

### 8. linux remains unresolved

Current reality:

- the full `BaseDataSet.json` planning-only evaluation for linux did not finish in the available time
- linux cannot be handled by the current tests-only process with acceptable speed

Implication:

- linux needs its own planning/indexing path
- do not keep applying generic multi-branch heuristics and assume they scale

---

## Existing tests-only artifacts

- script: `workflow/VulnVersion/tests/analyze_step3_planning.py`
- subset report: `workflow/VulnVersion/tests/step3_planning_report_30/`
- per-repo full reports: `workflow/VulnVersion/tests/step3_repo_reports/`

These artifacts should be used as the baseline for the next round of Step3 planning redesign.

## Final conclusion

Current Step3 is **not yet dataset-adapted**.

The key failure is:

- `tag_plan.json` often does not fully cover `affected_version`

So the next work on Step3 must follow this rule:

- **first fix planning coverage**
- **then fix planning cost**

Any optimization that reduces candidate count while further lowering GT coverage is the wrong direction.
