# CWE-770 Stage 1 View
Name: Allocation of Resources Without Limits or Throttling

## Goal

在 patch chunk 级别判断哪些改动最可能直接修复了该 CWE 的根因，哪些只是支撑性修改，哪些只是上下文或无关改动。

## Mechanism Summary

The product allocates a reusable resource or group of resources on behalf of an actor without imposing any intended restrictions on the size or number of resources that can be allocated.

## PRIMARY_FIX Signals

- add explicit validation
- constrain state before sink
- fail closed on invalid condition

## SUPPORTING_FIX Signals

- Introduces helpers, wrappers, or state propagation needed by the main fix
- Adds error handling or early return logic that makes the main fix effective
- Refactors data/control flow so the primary validation can dominate the sink/path

## CONTEXTUAL_CHANGE Signals

- comment-only change
- rename-only change
- logging-only change
- style refactor without changing the sensitive path

## High-Value Clues

- restrictions
- allocation
- throttling
- allocated
- allocates
- imposing
- intended
- reusable

## Dangerous Generic Tokens

以下 token 过于常见，不能单独作为 chunk 角色判断依据：

- size
- len
- length
- count
- index
- idx
- buf
- data
- value
- ptr

## Stage 1 Focus

- direct change to vulnerable sink or validation site
- changes that alter boundary, lifecycle, policy, or authorization relation
- supporting helper or error-propagation logic needed by the main fix

## Stage 1 Avoid

- comment-only or naming-only changes
- generic logging changes without security semantics
- refactors unrelated to the sensitive sink/path
