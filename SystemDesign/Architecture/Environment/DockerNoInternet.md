# VulnVersion 离线版 Docker 说明

## 1. 定位

本文件用于概括 `docker/NoInternet` 这套方案的作用、边界和使用方式。

它服务于以下场景：

1. 目标机器无法访问外网
2. 需要跨机器离线复现实验
3. 需要把目标待测仓库的 Git 历史一并带入环境
4. 需要在不改 VulnVersion 代码的前提下完成离线运行

---

## 2. 目录对应关系

离线版 Docker 的实现目录是：

```text
E:\AI\Agent\workflow\docker\NoInternet
```

该目录中最重要的文件有：

1. `Dockerfile`
2. `docker-entrypoint.sh`
3. `run_vulnversion.sh`
4. `.env.example`
5. `opencode.offline.json`
6. `README.md`
7. `repo-bundles/`

其中：

- `repo-bundles/` 是离线 Git 资产的存放目录
- `Dockerfile` 负责把 bundle、源码和运行环境打进镜像

---

## 3. 这套方案的核心设计

### 3.1 为什么使用 bundle

离线版不依赖运行时 `git clone` 目标 repo，而是提前在联网机器上把目标仓库打成：

```text
<repo>.bundle
```

然后放入：

```text
docker/NoInternet/repo-bundles/
```

原因是：

1. bundle 可以携带完整 Git 对象、commit graph、tag 和 branch refs
2. 只要使用完整仓库生成 bundle，VulnVersion 当前依赖的 Git 能力都能保留
3. 可以跨机器离线分发
4. 不需要容器在运行时访问外网

### 3.2 对 VulnVersion 的兼容性

当前 VulnVersion 依赖大量 Git 历史操作，包括：

1. `git log`
2. `git show`
3. `git grep`
4. `git blame`
5. `git merge-base`
6. `git rev-list --ancestry-path`
7. `git log -S/-G/-L`
8. `git tag`

离线版的关键要求是：

1. bundle 必须来自完整仓库
2. bundle 必须用 `--all` 生成
3. 容器内必须恢复成普通工作树仓库，而不是 bare repo

在这个前提下，当前 VulnVersion 不需要额外改代码。

### 3.3 OpenCode 和模型接入

离线版同样统一使用**项目根** `opencode.json`。

默认策略是：

1. 镜像里使用 env 驱动的 `opencode.offline.json` 模板
2. 运行时通过 `.env` 或 `--env-file` 指定：
   - `OPENAI_BASE_URL`
   - `OPENAI_API_KEY`
   - `OPENCODE_PROVIDER_ID`
   - `OPENCODE_MODEL_ID`

这意味着：

1. 镜像本身不 bake 真实模型密钥
2. 也不依赖用户家目录下的 OpenCode 全局配置

### 3.4 环境管理

离线版同样要求使用 Conda，并在 `VulnVersion` conda 环境中运行：

1. `opencode serve`
2. `python main.py`

原因和联网版一致：

1. 统一环境规格
2. 方便多机器复现
3. 减少本地系统 Python / Node 环境差异带来的问题

---

## 4. 适合什么时候使用

推荐在以下情况下使用离线版 Docker：

1. 目标机器没有外网
2. 需要交付一个可离线运行的实验环境
3. 需要在不同 Ubuntu 或虚拟机之间迁移同一套镜像
4. 需要确保目标 repo 历史完全随镜像资产一起分发

不推荐在以下情况下使用：

1. 你希望源码和 repo 都随 GitHub 持续更新
2. 你不想维护 bundle 生成流程
3. 你希望镜像尽可能轻量

---

## 5. 运行流程

离线版的典型运行流程是：

1. 在联网机器上生成全部 repo bundle
2. 将 bundle 放入 `docker/NoInternet/repo-bundles/`
3. 用 `Dockerfile` 构建离线镜像
4. 通过 `docker save` / `docker load` 跨机器迁移镜像
5. 容器启动时执行 `docker-entrypoint.sh`
6. 入口脚本把 bundle 恢复到 `repo/<name>/`
7. 调用 `run_vulnversion.sh`
8. `run_vulnversion.sh` 启动 OpenCode 并运行 `main.py`

---

## 6. 你需要准备什么

使用离线版 Docker 时，通常需要准备：

1. 正确生成的 repo bundle
2. 完整的离线镜像
3. 一份运行时 `.env`
4. 正确的 `VV_REPOS`
5. 正确的 `VV_DATASET`
6. 可访问的大模型服务

这里需要特别注意：

离线版 Docker 的“离线”主要指：

1. 不依赖外网下载源码
2. 不依赖外网下载目标 repo

它**不一定意味着大模型服务也必须在容器内部**。  
如果你的 LLM API 在本地局域网或同机部署，仍然可以通过 `.env` 指向该 endpoint。

---

## 7. 优点与代价

### 优点

1. 适合严格离线复现
2. 目标 repo 历史可控且随镜像一起交付
3. 不依赖 GitHub 或官方 repo 站点的可用性
4. 不需要修改 VulnVersion 代码即可工作

### 代价

1. 需要额外维护 bundle 生成流程
2. 镜像体积通常更大
3. 更新目标 repo 或源码时，通常需要重新构建镜像

---

## 8. 一句话结论

`docker/NoInternet` 适合“无外网、要完整携带 Git 历史、要跨机器离线复现”的 VulnVersion 运行环境。  
它的核心特征是：**源码和离线 Git 资产都提前打包进镜像，运行时不再依赖联网 clone。**
