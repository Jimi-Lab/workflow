# VulnVersion 联网版 Docker 说明

## 1. 定位

本文件用于概括 `docker/Internet` 这套方案的作用、边界和使用方式。

它服务于以下场景：

1. 新机器可以联网
2. 需要从 GitHub 获取最新 `VulnVersion` 源码
3. 需要按需下载目标待测仓库
4. 需要通过 OpenCode 接入内建 provider 或自定义 OpenAI-compatible 大模型
5. 需要支持多机器部署和多人复现

---

## 2. 目录对应关系

联网版 Docker 的实现目录是：

```text
E:\AI\Agent\workflow\docker\Internet
```

该目录中最重要的文件有：

1. `FinallBuild.md`
2. `Dockerfile`
3. `docker-entrypoint.sh`
4. `run_vulnversion.sh`
5. `.env.example`
6. `opencode.internet.json`
7. `README.md`

其中：

- `FinallBuild.md` 是最终规格文档
- `Dockerfile` 是实际构建逻辑
- `docker-entrypoint.sh` 是容器入口
- `run_vulnversion.sh` 是一键运行脚本

---

## 3. 这套方案的核心设计

### 3.1 主项目源码来源

联网版镜像构建时，通过 GitHub 获取 `VulnVersion` 主项目源码。

当前约定仓库为：

```text
https://github.com/Jimi-Lab/VulnVersion.git
```

这意味着：

1. 本地宿主机不必预先复制整套源码进镜像
2. 多机器构建时可以统一从同一 GitHub 仓库拉取
3. 你后续更新 `main` 分支后，联网版 Docker 可以直接复用新源码

### 3.2 目标 repo 的获取方式

联网版不把 FFmpeg、curl、openssl、linux 等目标仓库直接打进镜像。

目标 repo 由：

```text
repo/clone_repos.py
```

在容器运行时按需下载。

默认行为是：

1. 不自动下载任何目标 repo
2. 只有显式设置 `VV_REPOS` 时才下载
3. 可以只下载一个 repo，也可以下载多个 repo

### 3.3 OpenCode 和模型接入

联网版 Docker 统一使用**项目根** `opencode.json`，不再依赖：

1. `.opencode/opencode.json`
2. `~/.config/opencode/opencode.json`

模型接入分两层：

1. `opencode.json`
   作用：定义 provider、model、OpenAI-compatible endpoint 结构
2. `.env`
   作用：选择当前使用哪个 provider 和 model，并注入实际运行参数

因此联网版容器的推荐方式是：

1. 保留项目根 `opencode.json`
2. 运行时通过 `.env` 或 `--env-file` 传入模型配置

### 3.4 环境管理

联网版 Docker 明确要求使用 Conda。

原因是：

1. `environment.yml` 是 VulnVersion 当前统一的环境规格
2. Docker 内和本地直接 `git clone` 的复现方式都应尽量共用这套环境描述
3. `opencode serve` 和 `python main.py` 都应在 `VulnVersion` conda 环境中执行

---

## 4. 适合什么时候使用

推荐在以下情况下使用联网版 Docker：

1. 机器可以访问 GitHub
2. 机器可以访问目标待测仓库的官方源
3. 机器可以访问你配置的大模型 API endpoint
4. 你希望镜像体积相对可控，不把 9 个 repo 全部打进镜像
5. 你希望后续源码更新后，可以较容易重新构建镜像

不推荐在以下情况下使用：

1. 目标环境彻底断网
2. 需要完全离线交付
3. 无法访问 GitHub 或官方 repo 源

---

## 5. 运行流程

联网版的典型运行流程是：

1. 用 `Dockerfile` 构建镜像
2. 容器启动时执行 `docker-entrypoint.sh`
3. 入口脚本创建 `repo/` 和 `Result/` 目录
4. 若设置了 `VV_REPOS`，则调用 `repo/clone_repos.py` 下载目标 repo
5. 调用 `run_vulnversion.sh`
6. `run_vulnversion.sh` 启动 OpenCode
7. OpenCode 健康检查通过后，再运行 `python main.py --dataset ...`

---

## 6. 你需要准备什么

使用联网版 Docker 时，通常需要准备：

1. 可访问 GitHub 的网络环境
2. 可访问目标 repo 官方源的网络环境
3. 可访问大模型 endpoint 的网络环境
4. 一份运行时 `.env`
5. 正确的 `VV_REPOS`
6. 正确的 `VV_DATASET`

最关键的运行时变量通常是：

1. `OPENAI_BASE_URL`
2. `OPENAI_API_KEY`
3. `OPENCODE_PROVIDER_ID`
4. `OPENCODE_MODEL_ID`
5. `VV_REPOS`
6. `VV_DATASET`

---

## 7. 优点与代价

### 优点

1. 适合持续开发和多机器构建
2. 容器不必预装全部目标 repo
3. 主项目源码和 Docker 方案可以随着 GitHub 主线同步更新
4. 自定义 LLM API 接入灵活

### 代价

1. 对网络依赖强
2. 目标 repo 的正确性和完整 tag 集需要在运行时验证
3. 构建和运行阶段都更依赖外部可用性

---

## 8. 一句话结论

`docker/Internet` 适合“可联网、要持续更新、要多机器部署”的 VulnVersion 复现环境。  
它的核心特征是：**源码从 GitHub 来，目标 repo 按需下载，模型通过项目根 `opencode.json` + `.env` 接入。**
