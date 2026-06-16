# VulnVersion Agent Instructions

VulnVersion is an ICSE-targeted research system for identifying CVE affected versions from a CVE and fix commit family.

For VulnVersion work, every top-down design principle must be backed by bottom-up evidence from the actual codebase, dataset, or artifacts before it can be treated as a valid method direction.

Required evidence types include at least one of:

- Source-level verification against the current VulnVersion implementation.
- Dataset-scale or representative-sample scripts under `tests/`.
- Fresh planner simulation, historical artifact replay, or real agent verification results.
- Explicit failure-case analysis showing where the proposal does and does not hold.

Rules:

- Do not present an untested design as an accepted Step3 method.
- If a proposal is not yet tested, label it as `hypothesis` and specify the exact test needed.
- Do not optimize only for the current 1128 CVE / 9 repo surface pattern without explaining the general mechanism and overfitting risk.
- Any Step3 design or code change must keep `E:\AI\Agent\workflow\SystemDesign\Architecture\Develop\step3.md` synchronized.
- For Step3, prioritize evidence-backed line-local affected interval discovery over unverified FIC/VIC recovery assumptions.
