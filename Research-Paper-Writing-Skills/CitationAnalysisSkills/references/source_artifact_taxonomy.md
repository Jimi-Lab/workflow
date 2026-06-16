# Source and Artifact Taxonomy

Use this reference whenever a paper may have source code, data, benchmark artifacts, appendices, or reproducibility materials.

Default policy: static analysis only. Inspect files, paths, manifests, configs, README text, script structure, APIs, imports, function/class definitions, data references, and paper-code consistency. Do not install dependencies, execute code, run tests, launch experiments, or reproduce results unless the user explicitly requests an execution/reproduction pass.

## Classification

```text
Type A: paper + source code + data/artifact
Type B: paper + source code only
Type C: paper + data/artifact only
Type D: paper only
Type U: unknown or unverified
```

Record how the type was determined:

```text
Evidence:
- local path:
- URL:
- paper footnote:
- artifact badge:
- appendix statement:
- user-provided note:
```

## Type A: Paper + Source Code + Data/Artifact

Analyze both paper and artifact layers.

Required checks:

```text
Paper Claims:
Implemented Components:
Unimplemented or Stubbed Components:
Dataset Availability:
Benchmark / Evaluation Scripts Visible by Static Inspection:
Static Reproduction Instructions or Missing Instructions:
Config Files:
Environment Constraints:
Paper-Code Mismatches:
Engineering Lessons for Our Paper:
```

Use this type to learn how strong papers connect claims, methods, experiments, and artifact evidence. Do not claim that the artifact reproduces results unless an explicit execution/reproduction pass was requested and completed.

## Type B: Paper + Source Code Only

Analyze implementation structure, but be careful with experimental claims.

Required checks:

```text
Implemented Components:
Missing Data:
Missing Evaluation Scripts:
Declared Entry Points:
Paper-Code Consistency:
Claims That Need Data Evidence:
```

## Type C: Paper + Data/Artifact Only

Analyze evaluation reproducibility, but do not infer implementation internals.

Required checks:

```text
Available Data:
Available Results:
Evaluation Protocol:
Missing Source:
Claims That Cannot Be Implementation-Checked:
```

## Type D: Paper Only

Analyze writing structure only.

Allowed:

```text
Problem framing
Motivation
Method description as stated
Experiment design as stated
Claim-evidence structure
Figure/table design
Related-work positioning
```

Not allowed:

```text
Inferring hidden implementation behavior
Claiming reproducibility
Using unstated source-code details
Treating method diagrams as verified code
```

## Consistency Check Template

```text
Claim:
Paper Location:
Artifact Evidence:
Source Evidence:
Consistency: supported / partially supported / unsupported / unclear
Analysis Mode: static-only / execution-requested
Notes:
Use in Our Paper: yes / no / with caution
```

## Missing Evidence Labels

Use specific labels:

```text
[NEEDS SOURCE] source code is needed to verify implementation.
[NEEDS ARTIFACT] data, benchmark, or script is needed to verify evaluation.
[NEEDS CITATION VERIFICATION] citation metadata must be checked.
[EXECUTION NOT REQUESTED] runtime behavior, reproducibility, or result regeneration was not checked because the default mode is static analysis only.
[PAPER-ONLY] statement is only supported by the paper text.
```
