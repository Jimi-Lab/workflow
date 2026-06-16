# Section Prompt Workflow

Use this reference when converting citation analysis into the user's own paper draft.

## Required Inputs

```text
Target Section:
User Instruction:
Our-Paper Evidence:
Agent Evidence Units:
Reference Section Analyses:
Cross-Paper Pattern:
Forbidden Claims:
Known Missing Evidence:
Style Constraints:
```

If `Our-Paper Evidence` is missing, draft only a scaffold or write `[NEEDS EVIDENCE]` placeholders.

## Abstract Drafting

Read:

```text
cross_paper/abstract_patterns.txt
Paper/reference/*/raw_extraction/agent_index.json
Paper/reference/*/analysis/01_abstract.txt
Paper/text/00_evidence_map.txt
```

Generate:

```text
1. Problem sentence
2. Gap sentence
3. Method sentence
4. Evidence/evaluation sentence
5. Contribution/result sentence
6. Scope/limitation sentence if needed
```

Do not invent numeric results.

## Introduction Drafting

Read:

```text
cross_paper/introduction_patterns.txt
Paper/reference/*/raw_extraction/agent_index.json
Paper/reference/*/analysis/02_introduction.txt
Paper/text/00_evidence_map.txt
```

Generate a paragraph-level introduction:

```text
P1: broad problem and why it matters.
P2: concrete gap and failure of current practice.
P3: task-specific challenges.
P4: key idea and system preview.
P5: contributions.
P6: optional paper organization.
```

Every contribution must map to our-paper evidence or be marked `[NEEDS EVIDENCE]`.

## Background and Motivation Drafting

Read:

```text
cross_paper/background_motivation_patterns.txt
Paper/reference/*/raw_extraction/agent_index.json
Paper/reference/*/analysis/03_background_motivation.txt
Paper/text/00_evidence_map.txt
```

Generate:

```text
Domain setup:
Task definition:
Motivating case:
Why prior methods are insufficient:
Transition to method:
```

Do not over-explain generic background. Focus on concepts needed for the method.

## Method Drafting

Read:

```text
cross_paper/method_patterns.txt
Paper/reference/*/raw_extraction/agent_index.json
Paper/reference/*/analysis/05_method.txt
Paper/text/00_evidence_map.txt
Project source files and design docs
```

Generate:

```text
System overview:
Core abstraction:
Pipeline:
Algorithms:
Artifacts:
Failure handling:
```

Separate implemented facts from design goals.

## Experiment and Evaluation Drafting

Read:

```text
cross_paper/experiment_patterns.txt
cross_paper/evaluation_patterns.txt
Paper/reference/*/raw_extraction/agent_index.json
Paper/reference/*/analysis/06_experiments.txt
Paper/reference/*/analysis/07_evaluation.txt
Paper/text/00_evidence_map.txt
Local result artifacts
```

Generate:

```text
Research questions:
Dataset:
Baselines:
Metrics:
Protocol:
Results:
Analysis:
Limitations:
```

Do not invent experiments. If results are not available, write an experiment plan and mark missing results.

## Output Quality Checklist

Before returning a draft:

```text
Does each factual claim have our-paper evidence?
Are reference papers used only for structure?
Were `partial` or `low` agent evidence units used only as retrieval hints?
Are missing results marked?
Are terms consistent?
Is wording original?
Is the draft ready to paste into LaTeX after cleanup?
```
