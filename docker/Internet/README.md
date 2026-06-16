# VulnVersion Internet Docker

本目录存放 **联网版 VulnVersion Docker** 的构建规范、构建文件和运行辅助脚本。

目标不是离线分发，而是：

1. 在可访问外网的环境中构建镜像
2. 支持多机器部署
3. 支持通过 GitHub 获取 `VulnVersion` 主项目源码
4. 支持按需下载目标 repo
5. 支持通过 OpenCode + 自定义 LLM API 运行 VulnVersion

---

## 文件说明

### [FinallBuild.md](/e:/AI/Agent/workflow/docker/Internet/FinallBuild.md)

这是**联网版 Docker 的最终规格文档**。

作用：

1. 规定下一步 Dockerfile 必须遵守的硬约束
2. 定义联网版 Docker 的目录结构、环境要求、OpenCode 配置方式
3. 规定目标 repo 的下载与校验要求
4. 规定哪些内容必须进镜像，哪些不能进镜像

如果其他文档与它冲突，应以它为准。

---

### [readmd.md](/e:/AI/Agent/workflow/docker/Internet/readmd.md)

这是联网版 Docker 的**较早设计文档 / 补充设计文档**。

作用：

1. 记录联网版 Docker 的设计背景
2. 补充一些实现动机和设计原因
3. 为 `FinallBuild.md` 提供上游设计上下文

它不是最终规格文件。  
实际落地时优先以 `FinallBuild.md` 为准。

---

### [Dockerfile](/e:/AI/Agent/workflow/docker/Internet/Dockerfile)

这是联网版镜像的**实际构建文件**。

作用：

1. 从 Ubuntu 基础镜像开始构建
2. 安装 Conda、git、curl、tini 等基础依赖
3. 从 GitHub clone `VulnVersion` 主项目源码
4. 用项目内 `environment.yml` 创建 `VulnVersion` conda 环境
5. 安装 OpenCode CLI
6. 覆盖项目根 `opencode.json` 为联网版安全模板
7. 部署运行脚本和容器入口

它决定“镜像里最终有什么”。

---

### [docker-entrypoint.sh](/e:/AI/Agent/workflow/docker/Internet/docker-entrypoint.sh)

这是容器启动时的**入口脚本**。

作用：

1. 进入 `/root/VulnVersion`
2. 创建 `repo/` 和 `Result/` 目录
3. 检查运行时 `.env`
4. 根据 `VV_REPOS` 决定是否下载目标 repo
5. 最后执行容器传入的命令

它不直接跑 `main.py`，而是负责做**容器级初始化**。

---

### [run_vulnversion.sh](/e:/AI/Agent/workflow/docker/Internet/run_vulnversion.sh)

这是联网版容器中的**一键运行脚本**。

作用：

1. 启动 `start_opencode.sh`
2. 等待 OpenCode `/global/health` 变为可用
3. 使用 conda 环境运行：

```bash
python main.py --dataset ...
```

如果你希望“一条命令跑 VulnVersion”，就是用这个脚本。

---

### [.env.example](/e:/AI/Agent/workflow/docker/Internet/.env.example)

这是联网版容器运行时的**环境变量模板**。

作用：

1. 提供 `.env` 的示例写法
2. 说明如何选择 provider / model
3. 说明如何配置：
   - `OPENAI_BASE_URL`
   - `OPENAI_API_KEY`
   - `OPENCODE_PROVIDER_ID`
   - `OPENCODE_MODEL_ID`
4. 给出 `minimaxlocal`、`xiaoaiplus`、`c402` 等 provider 的示例

它不会被自动当成真实 `.env` 使用，通常应复制成运行时 `.env` 或用 `docker run --env-file` 传入。

---

### [opencode.internet.json](/e:/AI/Agent/workflow/docker/Internet/opencode.internet.json)

这是联网版镜像使用的**项目根 `opencode.json` 模板**。

作用：

1. 定义联网版 Docker 中允许使用的 OpenCode provider
2. 使用 env 驱动的方式定义自定义 OpenAI-compatible endpoint
3. 避免把你本地真实的 `opencode.json` 连同真实 key 一起 bake 进镜像

当前包含的 provider：

1. `local-openai`
2. `minimaxlocal`
3. `xiaoaiplus`
4. `c402`

它的定位是：**镜像安全模板**，而不是你本机项目的真实配置备份。

---

## 这些文件之间的关系

推荐按下面顺序理解：

1. [FinallBuild.md](/e:/AI/Agent/workflow/docker/Internet/FinallBuild.md)  
   看规范，知道应该做成什么样
2. [Dockerfile](/e:/AI/Agent/workflow/docker/Internet/Dockerfile)  
   看镜像是怎么构建的
3. [docker-entrypoint.sh](/e:/AI/Agent/workflow/docker/Internet/docker-entrypoint.sh)  
   看容器启动时做什么
4. [run_vulnversion.sh](/e:/AI/Agent/workflow/docker/Internet/run_vulnversion.sh)  
   看如何一键运行 VulnVersion
5. [.env.example](/e:/AI/Agent/workflow/docker/Internet/.env.example)  
   看运行时应传哪些环境变量
6. [opencode.internet.json](/e:/AI/Agent/workflow/docker/Internet/opencode.internet.json)  
   看 OpenCode provider 是如何定义的

---

## 运行时依赖哪些项目内文件

联网版 Docker 最终依赖的是 GitHub 上 `VulnVersion` 仓库中的这些内容：

1. `main.py`
2. `vulnversion/`
3. `DataSet/BaseDataSet.json`
4. `DataSet/BaseDataSet_30.json`
5. `DataSet/BaseDataTest.json`
6. `DataSet/BaseData_nvd.json`
7. `DataSet/nvd_crawler.py`
8. `repo/clone_repos.py`
9. `.opencode/skills`
10. `.opencode/tools`
11. `environment.yml`
12. `start_opencode.sh`
13. `vuln_config.json`

而本目录下的文件主要是：

- 覆盖默认配置
- 提供容器构建与运行逻辑

---

## 当前设计的关键点

### 1. 不再依赖 `.opencode/opencode.json`

联网版 Docker 已统一到：

- **项目根 `opencode.json`**

而不是旧的：

- `.opencode/opencode.json`

### 2. 不依赖 `~/.config/opencode/opencode.json`

新机器运行 VulnVersion 时，不应把用户家目录下的 OpenCode 全局配置作为前提。

### 3. 使用 env 驱动的自定义 LLM API

也就是说：

1. provider 定义在项目根 `opencode.json`
2. 运行时 endpoint / key / model 由 `.env` 提供

### 4. 默认不下载任何目标 repo

只有设置了：

```bash
VV_REPOS=curl
```

或类似值时，`docker-entrypoint.sh` 才会调用 `repo/clone_repos.py` 去下载 repo。

---

## 推荐使用方式

### 方式 1：进入容器后手工运行

```bash
docker run --rm -it \
  --env-file my-runtime.env \
  vulnversion-internet:latest
```

进容器后再执行：

```bash
python repo/clone_repos.py --repos curl
./start_opencode.sh
python main.py --dataset DataSet/BaseDataTest.json --no-watch
```

### 方式 2：一键运行

```bash
docker run --rm -it \
  --env-file my-runtime.env \
  -e VV_REPOS=curl \
  -e VV_DATASET=DataSet/BaseDataTest.json \
  vulnversion-internet:latest \
  vv-run
```

---

## 最后一句话

如果你只想知道每个文件最直接的用途：

- `FinallBuild.md`：最终规范
- `readmd.md`：历史设计说明
- `Dockerfile`：怎么构建镜像
- `docker-entrypoint.sh`：容器启动时做什么
- `run_vulnversion.sh`：怎么一键跑 VulnVersion
- `.env.example`：运行时变量模板
- `opencode.internet.json`：镜像内用的 OpenCode provider 模板
