# Tag And Topology

本文件对应 Git 官方 `git-tag`、`git-merge-base`、`git-show-ref`。

官方参考：
- https://git-scm.com/docs/git-tag
- https://git-scm.com/docs/git-merge-base
- https://git-scm.com/docs/git-show-ref

## Goal

判断 fix 是否传播到某条线、某 tag 是否包含某 commit、以及两个版本之间的祖先关系。

## Primary Commands

```bash
git tag -l --contains <commit>
git tag -l --no-contains <commit>
git tag -l --merged <commit>
git tag -l --points-at <object>
git merge-base <a> <b>
git merge-base --is-ancestor <older> <newer>
git show-ref --verify <ref>
git rev-list --ancestry-path <older>..<newer>
git rev-list --ancestry-path --reverse <older>..<newer>
```

## Usage

- `--contains`
  哪些 tag 已包含 fix commit
- `--no-contains`
  哪些 tag 仍在 fix 之前
- `--merged`
  哪些 tag 所指对象已并入某 commit
- `merge-base`
  算共同祖先
- `--is-ancestor`
  快速判断祖先关系
- `rev-list --ancestry-path`
  抽取两个点之间真正的祖先路径

## Rules

- 判断 fix 传播时，优先使用拓扑关系，不要仅凭 tag 命名猜。
- `--contains` 与 `--merged` 语义不同，不要混用。
- 需要验证版本路径时，`ancestry-path` 比普通 `rev-list` 更可靠。

## Common Mistakes

- 把日期顺序误当祖先顺序
- 把相似 tag 名当成同一 release line
- 只看 `contains` 不看 merge-base/ancestor 关系
