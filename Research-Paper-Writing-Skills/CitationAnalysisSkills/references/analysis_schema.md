# Reference Paper Analysis Schema

Use this template to decompose each accepted paper. Keep the output analytical and section-oriented. Do not write a generic summary.

## 00_meta.txt

```text
Paper ID:
Title:
Venue / Year:
Authors:
Artifact Type: Type A / B / C / D / U
Input Files:
Source / Artifact Path:
Analysis Status:
Agent Index Status:
Main Topic:
Why This Paper Is Relevant:
Citation Metadata Status:
Missing Evidence:
```

## 01_abstract.txt

Extract the abstract's argument structure:

```text
Problem:
Gap:
Core Idea:
Method:
Evaluation Setup:
Main Results:
Contribution Wording:
Limitations or Scope Boundaries:
Reusable Writing Pattern:
Relevance to Our Paper:
Do Not Borrow:
```

## 02_introduction.txt

Decompose the introduction at paragraph level:

```text
Opening Context:
Why the Problem Matters:
Concrete Pain Point:
Motivating Example:
Prior Work Framing:
Why Prior Work Is Insufficient:
Technical Challenges:
Key Insight:
System / Method Preview:
Contribution List:
Claim-Evidence Structure:
Agent Evidence Anchors:
Paragraph Map:
Reusable Moves:
Risks for Our Paper:
```

For `Paragraph Map`, use:

```text
P1:
  Function:
  Main Claim:
  Evidence Type:
  Transition:
```

## 03_background_motivation.txt

```text
Domain Concepts Introduced:
Task Definition:
Threat Model / Assumptions:
Motivating Case:
Why the Case Is Chosen:
Definitions Needed by Readers:
How Background Leads to Method:
Writing Pattern:
Relevance to Our Paper:
Agent Evidence Anchors:
```

## 04_problem_definition.txt

```text
Input:
Output:
Objects / Entities:
Formal Definitions:
Objective:
Constraints:
Evaluation Target:
Boundary Conditions:
What Is Not Solved:
Reusable Formalization Pattern:
```

## 05_method.txt

```text
System Overview:
Pipeline Stages:
Core Algorithm:
Data Structures:
Model / Agent Components:
Design Choices:
Why Each Choice Is Needed:
Failure Handling:
Complexity / Cost Discussion:
Pseudocode or Algorithm Blocks:
Static Reproducibility Signals:
Agent Evidence Anchors:
Writing Pattern:
```

## 06_experiments.txt

```text
Research Questions:
Datasets:
Baselines:
Metrics:
Experimental Protocol:
Implementation Details:
Hyperparameters / Settings:
Hardware / Environment:
Static Reproducibility Materials:
Execution Status:
What Is Measured:
What Is Not Measured:
Agent Evidence Anchors:
Writing Pattern:
```

## 07_evaluation.txt

```text
Main Results:
Per-RQ Findings:
Ablation:
Sensitivity Analysis:
Case Study:
Efficiency:
Error Analysis:
Statistical / Validity Notes:
How Claims Are Supported:
Unsupported or Weakly Supported Claims:
Agent Evidence Anchors:
Writing Pattern:
```

## 08_limitations_ethics.txt

```text
Stated Limitations:
Threats to Validity:
Ethical Considerations:
Security / Misuse Discussion:
Responsible Disclosure:
Scope Boundaries:
Writing Pattern:
Relevance to Our Paper:
```

## 09_figures_tables.txt

```text
Figure / Table Inventory:
For each figure/table:
  ID:
  Agent Evidence Unit ID:
  Purpose:
  Evidence Shown:
  Placement in Argument:
  Extraction Confidence:
  Repair Needed:
  Citation Readiness:
  Figure Readiness:
  Design Pattern:
  Could Inspire Our Paper? yes/no
Required Figures for Our Paper:
```

## 10_writing_patterns.txt

```text
Best Structural Moves:
Best Transition Moves:
Best Contribution Wording Pattern:
Best Method Overview Pattern:
Best Experiment Framing Pattern:
Useful Phrases to Paraphrase Structurally:
Patterns to Avoid:
```

Do not copy wording directly into the user's paper. Convert phrase-level observations into abstract patterns.

## 11_relevance_to_our_paper.txt

```text
Direct Relevance:
Indirect Relevance:
Useful for Which Section:
Comparable Task Elements:
Comparable Method Elements:
Comparable Evaluation Elements:
What We Can Borrow Structurally:
What We Cannot Borrow:
Evidence Needed Before Use:
Priority: high / medium / low
```
