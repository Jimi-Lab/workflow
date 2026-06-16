# Stage 1 Git Playbook

目标：给 patch chunk 做角色分类。Stage 1 是 judge-only 任务，只判断 chunk 是否与漏洞修复直接相关，不做 tag plan、scan order 或 affected range。

## Recommended Order

1. `git show <fix_commit>^:<file>`
2. `git show <fix_commit>:<file>`
3. 如需定位符号：`git grep -F -n '<symbol>' <fix_commit>`
4. 如需看函数历史：`git log -L :<func>:<file> <fix_commit>`

## Focus

- 变更是否直接触及 sink、guard、allocation、lifecycle
- 变更是否只是支撑性 helper / error propagation
- 变更是否只是注释、命名、日志或结构整理
- 判断依据必须来自 fix patch 及其直接上下文，不要根据后续版本范围反推 chunk 角色
