# CWE-363 Stage 2 View
Name: Race Condition Enabling Link Following

## Goal

为 RCI 构造提供结构化先验，重点指导 root cause、anchor、predicate、guard 和 scope 的选择。

## Root Cause Template

推荐围绕以下机制写 root cause：

- untrusted or insufficiently validated state reaches sensitive operation
- Architecture and Design
- Implementation

典型敏感 sink/path：

- security-relevant operation

## Preferred Anchor

- Prefer the function, block, or local region where the sensitive relation is visible
- Prefer code where the sink/path and its guarding relation can be observed together
- Avoid anchoring on wrappers that hide the vulnerability mechanism

## Preferred Predicate Kinds

- ordered_tokens
- proximity
- token_all

## Discouraged Predicate Kinds

- token_any

## Preferred Scope

- function
- anchor_window

## Recommended Predicate Templates

- security-sensitive sink without sufficient guard
- explicit validation before sink
- reject invalid state
- safe helper/wrapper

## Recommended Guard Templates

- same logical object and same sink context

## Dangerous Generic Tokens

以下 token 不能单独构成 predicate：

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

## Stage 2 Focus

- anchor at the sink or dominant validation block
- prefer predicates that encode relations, not lone generic tokens
- choose function-local or anchor-window scope whenever possible

## Stage 2 Avoid

- whole-repo unscoped token matches
- predicates that rely on generic names alone
- anchors in wrappers that lack the core vulnerability mechanism
