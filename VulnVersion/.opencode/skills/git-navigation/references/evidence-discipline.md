# Evidence Discipline

## Core Principle

Git 命令的作用是“定位并读取证据”，不是替代推理。

## Required Discipline

1. 每个判断都要能回指到 `ref + path + line`。
2. `git grep` 命中后，必须读上下文。
3. 路径不存在时，必须说明是否做过 rename/topology 检查。
4. `NOT_AFFECTED` 不能只靠“没搜到某个 token”。
5. `AFFECTED` 不能只靠“搜到了 generic token”。
6. Stage 3 verdict 只能使用当前 tag 的代码证据；neighbor verdict、GT affected tags、affected range、tag plan、scan order 和 early stop 不能作为证据。
7. 当前 tag 的 `git show <tag>:<path>` 证据优先于 commit message、advisory 和 CWE 先验。

## Strong Evidence

- 在目标 tag 的同一函数/局部窗口中读到 vuln relation
- 在目标 tag 的同一函数/局部窗口中读到 fix relation
- 明确的 rename / ancestry / contains 关系
- 可复核的 blame / line-history 支撑

## Weak Evidence

- 单行 grep
- 只读 commit message
- 只看当前工作区代码
- 只看 tag 名称模式
- planner state 或其他 tag verdict

## Output Pattern

- 读了哪个 `ref`
- 打开了哪些文件
- 证据位于哪些行
- 为什么这些证据支持或反驳漏洞关系
- 若使用了 topology，只把它作为解释传播关系的辅助，不把它替代当前 tag 的代码证据
