# CWE-476 Stage 2 View
Name: NULL Pointer Dereference

## Goal

为 RCI 构造提供结构化先验，重点指导 root cause、anchor、predicate、guard 和 scope 的选择。

## Root Cause Template

推荐围绕以下机制写 root cause：

- unchecked return value
- optional allocation/use path
- Implementation

典型敏感 sink/path：

- dereference/call through possibly-null pointer

## Preferred Anchor

- Prefer the function, block, or local region where the sensitive relation is visible
- Prefer code where the sink/path and its guarding relation can be observed together
- Avoid anchoring on wrappers that hide the vulnerability mechanism

## Preferred Predicate Kinds

- ordered_tokens
- proximity
- token_all

## Discouraged Predicate Kinds

- regex

## Preferred Scope

- function
- basic_block
- anchor_window

## Recommended Predicate Templates

- pointer use without preceding null check
- if (!ptr)
- if (ptr == NULL)
- return error on null

## Recommended Guard Templates

- same pointer variable in check and use

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
