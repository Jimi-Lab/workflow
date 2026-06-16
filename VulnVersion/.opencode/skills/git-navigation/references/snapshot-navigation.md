# Snapshot Navigation

本文件对应 Git 官方 `git-show`、`git-ls-tree`、`git-cat-file`。

官方参考：
- https://git-scm.com/docs/git-show
- https://git-scm.com/docs/git-ls-tree
- https://git-scm.com/docs/git-cat-file

## Goal

在不 checkout 的情况下读取某个 tag/commit 的真实代码与目录结构。

## Primary Commands

```bash
git show <ref>:<path>
git cat-file -e <ref>:<path>
git ls-tree --name-only <ref> <dir>/
git ls-tree -r --name-only <ref> <dir>/
git cat-file -t <object>
git cat-file -s <object>
```

## Usage Pattern

1. 先 `git cat-file -e <ref>:<path>` 判断路径是否存在。
2. 若存在，再 `git show <ref>:<path>` 读内容。
3. 若不存在，先列目录，再查 rename。
4. 只需要目录结构时，用 `ls-tree`，不要直接乱 grep。

## When To Use

- 读取 anchor file
- 验证 tag 上某文件是否仍存在
- 在 rename 后重新定位目录
- 区分 blob/tree/tag/commit 对象

## Common Mistakes

- 路径不存在时立即判漏洞已消失
- 需要目录枚举时仍用 `git show`
- 不确认对象类型就直接读取
