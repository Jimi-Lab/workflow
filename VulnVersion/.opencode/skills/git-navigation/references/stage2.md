# Stage 2 Git Playbook

目标：构造 root cause、anchor、predicate、guard。Stage 2 是 judge-only 证据归纳任务，不枚举 tag，不输出 affected range。

## Recommended Order

1. `git show <vuln_commit>:<path>`
2. `git show <fix_commit>:<path>`
3. `git log --follow --name-status -- <path>`
4. `git log -S'<token>' --oneline <vuln_commit>..<fix_commit>`
5. `git log -G'<regex>' --oneline <vuln_commit>..<fix_commit>`
6. `git log -L :<func>:<file> <vuln_commit>..<fix_commit>`

## Focus

- anchor 在 vuln/fix 两端是否都能定位
- token 是 generic 还是 truly distinctive
- rename/move 是否导致 anchor_at_vuln 与 anchor 不同
- predicate 必须绑定 scope、证据 ref 和负例风险；不能只保存 generic token
- guard 只能约束判别条件，不能编码 GT affected tags 或 planner state
