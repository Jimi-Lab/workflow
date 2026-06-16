# Revision Selection

本文件对应 Git 官方 `gitrevisions`。

官方参考：
- https://git-scm.com/docs/gitrevisions

## Goal

先把“你在读哪个对象”说清楚，再做任何搜索或判断。

## Core Forms

- `<rev>`
  指定某个 commit、tag、branch 或可解析对象
- `<rev>^`
  第一父提交
- `<rev>^2`
  第二父提交
- `<rev>~3`
  顺着第一父回退 3 代
- `<rev>:<path>`
  读取该 revision 中的某个 blob/tree 路径
- `<a>..<b>`
  在历史遍历里表示“从 b 可达、但不从 a 可达”

## Recommended Commands

```bash
git rev-parse --verify <rev>^{}
git show <rev>:<path>
git cat-file -e <rev>:<path>
```

## Rules

- 访问文件时优先用 `<rev>:<path>`，不要混用工作区路径。
- 遇到 annotated tag，先用 `rev-parse --verify <rev>^{}` 消解。
- 对 fix commit 的父版本，优先用 `<fix_commit>^`。
- 不要把 `HEAD` 当成某个历史 tag 的等价物。

## Common Mistakes

- 把 `<rev>` 当工作区快照理解
- 不区分 tag 对象和 commit 对象
- 在 `A..B` 语义上误以为同时包含 A 和 B
