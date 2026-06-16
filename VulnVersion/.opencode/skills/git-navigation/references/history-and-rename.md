# History And Rename

本文件对应 Git 官方 `git log` 与 Git Book 的 Searching 章节。

官方参考：
- https://git-scm.com/book/en/v2/Git-Basics-Viewing-the-Commit-History
- https://git-scm.com/book/en/v2/Git-Tools-Searching
- https://git-scm.com/docs/git-log
- https://git-scm.com/docs/git-blame

## Goal

定位引入点、rename、语义变更与行级历史。

## Primary Commands

```bash
git log --oneline --decorate <range> -- <path>
git log --follow --name-status -- <path>
git diff --name-status <old> <new> -- <path>
git log -S'<string>' --oneline <range>
git log -G'<regex>' --oneline <range>
git log -L :<func>:<file> <range>
git log -L <start>,<end>:<file> <range>
git blame --line-porcelain -L <start>,<end> <ref> -- <file>
```

## What Each One Is For

- `--follow`
  查路径 rename/move 线索
- `-S`
  查某个字符串“出现次数发生变化”的提交
- `-G`
  查 diff 中匹配某个模式的提交
- `-L`
  查函数或行区间的演化历史
- `blame`
  查某个最终行是谁引入或最后修改

## Rules

- 查 rename 时，优先 `log --follow`，必要时配合 `diff --name-status`。
- 查 token 引入点时，优先 `-S`；查模式变化时用 `-G`。
- `blame` 适合解释当前代码行来源，不适合独立证明整条漏洞逻辑。
- `-L` 是高价值命令，优先用于 anchor function 的精细历史跟踪。

## Common Mistakes

- 用 `--follow` 证明语义等价
- 把 `blame` 返回的最后修改者当成根因引入者
- 只查 commit message，不查实际 diff
