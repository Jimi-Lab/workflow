# Code Search

本文件对应 Git 官方 `git-grep`，以及 Git Book 的 Searching 章节。

官方参考：
- https://git-scm.com/docs/git-grep
- https://git-scm.com/book/en/v2/Git-Tools-Searching

## Goal

快速定位 token、符号、guard、sink，但不把 grep 命中当成最终证据。

## Preferred Commands

```bash
git grep -F -n '<token>' <ref> -- '*.c' '*.h'
git grep -n -C 3 '<pattern>' <ref>
git grep -c '<pattern>' <ref> -- '*.c' '*.h'
git grep -rl '<symbol>' <ref>
git grep -n -e '<p1>' --or -e '<p2>' <ref>
```

## Search Strategy

1. 先用 `-F` 做固定字符串命中。
2. 需要局部语义时，再加 `-C 3` 或更大上下文。
3. 只做存在性检查时，用 `-c`。
4. 只想找文件位置时，用 `-rl`。
5. 需要多个 token 协同时，用 `--or` 组合。

## Rules

- 默认先固定字符串，后 regex。
- 命中行后必须回读源文件上下文。
- 通用 token 如 `size`, `len`, `count`, `data` 不能单独作为漏洞证据。
- 搜不到不等于不存在，可能是 rename、wrapper、宏替换或 tag 差异。

## Common Mistakes

- 只看单行 grep 命中就下结论
- 用 regex 搜本可精确匹配的 token
- 忽略 path glob，导致无关文件污染结果
