# Stage 3 Git Playbook

目标：验证 planner 给定的单个 tag 是否满足 Step2 生成的漏洞存在性定理。Stage 3 是 judge-only 单 tag verdict 任务，不做 tag plan、scan order、early stop 或 affected range aggregation。

## Target-tag Theorem Judge

Stage3 的核心问题是：

```text
Does this target tag satisfy the Step2 vulnerability theorem?
```

因此 Git 操作必须围绕 Step2 的 root cause、anchor、vuln predicates、fix predicates 和 guards 展开。Agent 仍然可以自主调用 git，但搜索目的必须是验证目标 tag 的源码状态，而不是开放式探索整个 repo。

## Recommended Order

1. `git cat-file -e <tag>:<path>`
2. `git show <tag>:<path>`
3. `git grep -F -n '<token>' <tag>`
4. `git grep -n -C 3 '<pattern>' <tag>`
5. 若路径缺失：`git log --follow --name-status -- <path>`
6. 若需 release-line 判断：`git tag --contains <fix_commit>` / `git merge-base`
7. 若需路径链验证：`git rev-list --ancestry-path <older>..<newer>`

## Focus

- 先确认文件/函数是否存在
- 再确认 Step2 vuln predicates 是否在同一局部 scope 成立
- 再确认 fix predicates / guards 是否在同一局部 scope 阻断 root cause
- 最后只输出该 target tag 的 verdict，不输出 affected range

## Tag Snapshot Rule

- 判断 tag 时必须读取 `tag:path` 的真实快照。
- 不得用当前工作区文件替代 tag snapshot。
- `git grep` 只能定位候选文件或 token，最终 verdict 必须回到 `git show <tag>:<path>` 或等价上下文证据。
- 当前 tag 的代码证据优先级高于 commit message、advisory、CWE 先验和其他 tag 的 verdict。
- Step2 的 theorem 是判定上下文，不是当前 tag 已 affected 的证据。

## Failure-triggered Checks

- path missing：先查目录、rename/move 和 topology，不要直接判 `NOT_AFFECTED`。
- generic token overmatch：要求同一函数/局部窗口内出现 root-cause relation。
- fix-token overmatch：确认 fix predicate 与 root cause 在同一 scope，不把相似 guard 当作修复。
- rename/move ambiguity：先建立 path mapping，再读取 tag snapshot。
- weak negative evidence：只有 grep miss 不足以支持 `NOT_AFFECTED`。
