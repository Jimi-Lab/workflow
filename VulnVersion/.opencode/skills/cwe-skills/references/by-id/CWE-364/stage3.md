# CWE-364 Stage 3 View
Name: Signal Handler Race Condition

## Goal

在单个 tag 上验证该版本是否仍然表现出该 CWE 的危险关系，或是否已经包含足够强的修复关系。

## Verification Strategy

推荐搜索顺序：

- ptr = NULL
- reference count guard
- free/release followed by later use
- missing lifetime guard

## High-Signal Vulnerable Evidence

- free/release followed by later use
- missing lifetime guard
- signal
- handler
- race
- are

## High-Signal Fixed Evidence

- ptr = NULL
- reference count guard
- move free after last use

## Guard Checks

- same object identity
- same control-flow region

## Dangerous Generic Tokens

以下 token 不能单独支持 `NOT_AFFECTED`：

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

## Stage 3 Focus

- whether the sensitive sink/path still exists
- whether the fix relation is locally present in the same code region
- whether anchor relocation is required before concluding absence

## Stage 3 Avoid

- declaring NOT_AFFECTED from generic token absence alone
- assuming refactor/rename means vulnerability removal
- using broad token matches as final evidence
