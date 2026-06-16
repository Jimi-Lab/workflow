# VulnVersion Internet Dockerfile 最终构建规范

本文件是为**下一步编写联网版 Dockerfile**准备的最终规格说明。

目标不是解释概念，而是给 Codex 一个**可直接执行的 Dockerfile 编写规范**。

如果后续 `docker/Internet/Dockerfile`、`docker/Internet/docker-entrypoint.sh`、`docker/Internet/run_vulnversion.sh`、`VulnVersion/repo/clone_repos.py` 的实现与本文件冲突，**以本文件为准**。

---

## 0. 参考优先级

编写联网版 Dockerfile 时，参考优先级如下：

1. 本文件：`docker/Internet/FinallBuild.md`
2. `docker/Internet/readmd.md`
3. `docker/docker.md`
4. `docker/readme.md`

如果多份文档存在冲突，按以上顺序覆盖。

---

## 1. 最终目标

联网版 Docker 的目标不是“本机临时跑起来”，而是：

1. 支持**联网环境**下的构建与运行
2. 支持**多机器部署**
3. 支持**复现实验**
4. 支持**按需下载目标 repo**
5. 保持与离线版 NoInternet 方案的目录结构和运行方式尽量一致

联网版不是离线版的替代品。
如果目标环境**不能访问外网**，应使用 `docker/NoInternet` 方案，而不是 Internet 方案。

---

## 2. 交付物

下一步应生成至少以下文件：

1. `docker/Internet/Dockerfile`
2. `docker/Internet/docker-entrypoint.sh`
3. `docker/Internet/run_vulnversion.sh`

联网版还要依赖并部署项目内现有脚本：

4. `VulnVersion/repo/clone_repos.py`

如有必要，可额外生成：

5. `docker/Internet/.env.example`
6. `docker/Internet/opencode.internet.json`

但这两项是可选增强，不是最低交付要求。

---

## 3. 绝对约束

下面这些约束是**硬要求**：

1. 联网版 Dockerfile 必须从 GitHub 获取 `VulnVersion` 主项目源码，而不是依赖本地 `COPY` 整个源码目录。
2. GitHub 源地址先固定为：

```text
https://github.com/Jimi-Lab/VulnVersion.git
```

3. 必须支持 `VV_GIT_REF`，默认可为 `main`，但设计上必须允许固定 commit / tag。
4. 容器内项目根目录必须固定为：

```text
/root/VulnVersion
```

5. Docker 中**必须使用 Conda 统一管理 VulnVersion 环境**。
6. Conda 环境文件以项目根：

```text
environment.yml
```

为主。
7. Dockerfile 中必须写明 Conda 的安装与环境创建流程。
8. Python 环境基线为 `Python 3.11.3`。
9. 必须全局安装 OpenCode，并固定版本：

```bash
npm i -g opencode-ai@1.2.26
```

10. Conda 环境中必须包含 `git`、`curl`、`nodejs`、`npm`、`ripgrep`。
11. `repo/clone_repos.py` 必须用于联网下载 repo，不能复用 `clone_all_repos.py`。
12. 下载目标 repo 时，必须使用官方/权威 canonical URL，不得从本地已有仓库 remote 推断。
13. 下载目标 repo 时必须拉取**完整历史**和**全部 tag refs**。
14. `nvd_crawler.py` 的联网抓取逻辑，设计上必须依赖系统 `curl`，但不能写死 `curl.exe`。
15. `BaseData_nvd.json` 必须进入镜像。
16. 镜像内必须准备：

- `Result/`
- `repo/`

---

## 4. 明确不要做什么

下面这些做法在联网版 Dockerfile 中**禁止出现**：

1. 禁止 `COPY E:\...` 或任何 Windows 宿主机绝对路径。
2. 禁止把整个 `E:\AI\Agent\workflow` 作为运行依赖复制进镜像。
3. 禁止在联网版里直接复用：
   - `VulnVersion/repo/clone_all_repos.py`
4. 禁止通过猜测 URL 下载 repo，例如：

```text
https://github.com/{repo_name}/{repo_name}.git
```

5. 禁止使用：
   - `--depth 1`
   - partial clone
   - `--no-tags`
6. 禁止只校验“本地 tag 非空”就认为 repo 正确。
7. 禁止将真实 API key、真实 provider 配置硬编码进镜像。
8. 禁止绕开 `environment.yml` 直接只用 `pip install -r requirements.txt` 作为 Docker 主环境构建方式。
9. 禁止为了兼容旧逻辑在 Dockerfile 里做 `curl.exe` 假名 hack，**除非源码层仍未修正且你明确选择保留兼容层**。
10. 禁止在 Dockerfile 中默认下载全部目标 repo。

---

## 5. 容器内目录布局

最终容器内应具备如下布局：

```text
/root/VulnVersion/
  main.py
  opencode.json
  vuln_config.json
  requirements.txt
  environment.yml
  start_opencode.sh
  .env                  # 可由用户传入或运行时创建
  .opencode/
  DataSet/
    BaseDataTest.json
    BaseDataSet.json
    BaseDataSet_30.json
    BaseData_nvd.json
    nvd_crawler.py
  vulnversion/
  repo/
  Result/
```

联网版中，`repo/` 默认允许为空。
后续由 `repo/clone_repos.py` 按需填充。

---

## 6. 主项目源码获取方式

### 6.1 必须使用 Git clone

联网版 Dockerfile 必须在构建阶段通过 Git clone 获取主项目源码。

建议使用以下 build args：

```dockerfile
ARG VV_GIT_URL=https://github.com/Jimi-Lab/VulnVersion.git
ARG VV_GIT_REF=main
```

然后在构建阶段：

1. clone `VV_GIT_URL`
2. checkout `VV_GIT_REF`

### 6.2 关于 `main`

`main` 只能作为开发便利默认值。

真正的复现/分发场景推荐使用：

- 固定 commit
  或
- 固定 tag

### 6.3 必须记录构建源码版本

建议下一步 Dockerfile 至少做其中一项：

1. 写入 image label
2. 写入文件：

```text
/root/VulnVersion/.build_ref
```

里面记录：

- `VV_GIT_URL`
- `VV_GIT_REF`
- 实际 checkout commit SHA

这样容器启动后可以直接追溯镜像内源码版本。

---

## 7. Conda 环境管理规范

### 7.1 选择

联网版 Docker 必须使用：

- Conda
- 项目根 `environment.yml`

### 7.2 为什么必须使用 Conda

项目中虽然存在：

- [environment.yml](/e:/AI/Agent/workflow/VulnVersion/environment.yml)

但之前它过于精简，不足以承担完整复现职责。现在的目标是把它升级为：

- Docker 复现环境主入口
- 本地 clone 后复现的统一环境入口
- Python、git、curl、nodejs、npm、ripgrep 的统一管理入口

必须使用 Conda 的原因是：

1. 本地直接 clone 项目复现时，如果只靠 pip，很容易和宿主机已有环境冲突
2. VulnVersion 不只是 Python 项目，还依赖 Node/OpenCode、git、curl、ripgrep 等工具
3. Docker 复现和本地复现需要共享同一套环境描述文件
4. 即便镜像体积更大，也必须优先保证**环境一致性**和**复现稳定性**

### 7.3 `environment.yml` 的定位

`environment.yml` 现在应当成为：

- VulnVersion 全部环境的主描述文件
- Dockerfile 构建 Conda 环境的主入口
- 本地复现时首选的环境创建入口

### 7.4 `requirements.txt` 的定位

`requirements.txt` 应保留，但定位下调为：

- pip 辅助入口
- 非 Docker 主入口
- 非推荐的首选本地复现入口

### 7.5 依赖版本基线

当前确认下来的核心环境版本基线如下：

- Python `3.11.3`
- pip `25.0.1`
- git `2.49.0`
- curl `8.16.0`
- nodejs `22.13.0`
- npm：随 `nodejs` 包提供，不单独作为 conda 包安装
- ripgrep `15.1.0`
- OpenCode CLI `1.2.26`

当前确认下来的 Python 包版本如下：

- `pydantic==2.9.2`
- `jsonschema==4.25.1`
- `httpx==0.27.0`
- `beautifulsoup4==4.13.5`

### 7.6 当前未纳入最终环境的项

以下内容当前不应作为最终环境依赖写入：

- `grep-ast`
- `tqdm`
- `PyYAML`
- `networkx`
- `tiktoken`

原因：

1. 当前代码里没有实际导入和使用
2. 本机环境中也未安装
3. 它会制造“环境文件声明了但项目实际不需要”的噪声

### 7.7 依赖确认方法

当前环境基线不是凭经验估算，而是按下面三类信息收敛出来的：

1. 主运行链源码导入：
   - `main.py`
   - `vulnversion/`
   - `DataSet/`
   - `repo/clone_repos.py`
2. 当前本机已安装并可用的工具版本：
   - `python`
   - `git`
   - `curl`
   - `node`
   - `npm`
   - `opencode`
3. 当前项目中实际固定的 OpenCode 版本：
   - `.opencode/package.json` 中的 `@opencode-ai/plugin = 1.2.26`

### 7.8 Docker 中的推荐实现

推荐在 Dockerfile 中显式安装 Miniforge / Miniconda / Mambaforge 之一，然后：

```bash
conda env create -f environment.yml
```

之后所有运行命令都应通过：

```bash
conda run -n VulnVersion ...
```

或等价的 `conda activate VulnVersion` 后执行。

### 7.9 本地复现的推荐实现

如果用户把：

- `https://github.com/Jimi-Lab/VulnVersion.git`

拉到本地，推荐的第一步也应是：

```bash
conda env create -f environment.yml
conda activate VulnVersion
```

然后再执行：

- OpenCode 安装
- `.opencode` 依赖安装
- repo 下载
- `main.py`

这样可以最大限度避免本地环境冲突。

---

## 8. Node / OpenCode 环境规范

### 8.1 必装组件

必须安装：

- `nodejs`
- `npm`
- OpenCode CLI

安装命令固定为：

```bash
npm i -g opencode-ai@1.2.26
```

说明：

- npm 包名：`opencode-ai`
- 可执行文件名：`opencode`

### 8.2 项目内 Node 依赖

如果联网版需要安装项目内 Node 依赖，优先使用：

```bash
npm ci
```

而不是：

```bash
npm install
```

这样更可复现。

### 8.3 OpenCode 配置

OpenCode/provider 配置不能写死到镜像里。

镜像中只能放：

- 模板配置
- 占位配置

真实值必须来自：

1. 项目根 `opencode.json`
2. `.env`
3. `docker run --env-file`
4. 运行时环境变量
5. 用户挂载自定义项目根 `opencode.json`

这里的规则已经与当前 VulnVersion 源码对齐：

1. `start_opencode.sh` / `start_opencode.cmd` 会先加载项目根 `.env`
2. 然后在项目根启动 `opencode serve`
3. OpenCode 应读取**项目根** `opencode.json`
4. VulnVersion 客户端通过 `.env` 中的：
   - `OPENCODE_PROVIDER_ID`
   - `OPENCODE_MODEL_ID`
     选择要使用的 provider/model

禁止继续依赖：

- `~/.config/opencode/opencode.json` 作为项目运行前提
- `.opencode/opencode.json` 作为项目级 provider 配置源

项目根 `opencode.json` 的职责是：

- 定义 provider
- 定义 openai-compatible endpoint
- 定义 models

`.env` 的职责是：

- 选择当前运行使用哪个 provider/model
- 注入 machine-local 的 endpoint、api key、端口等变量

### 8.4 `.opencode` 本地依赖

除全局 OpenCode CLI 外，项目还存在：

- [VulnVersion/.opencode/package.json](/e:/AI/Agent/workflow/VulnVersion/.opencode/package.json)

当前固定为：

- `@opencode-ai/plugin = 1.2.26`

因此本地复现或 Docker 构建时，除了全局安装 OpenCode CLI，还应考虑安装 `.opencode` 层依赖。

### 8.5 自定义 OpenAI-compatible LLM API

联网版必须支持自定义 OpenAI-compatible endpoint。

推荐设计：

1. 在项目根 `opencode.json` 中定义 provider，例如：
   - `minimaxlocal`
   - `xiaoaiplus`
   - `c402`
   - 或一个通用的 `local-openai`
2. 在 `.env` 中设置：
   - `OPENCODE_PROVIDER_ID`
   - `OPENCODE_MODEL_ID`
3. 若 provider 的 `baseURL` / `apiKey` 使用 env 引用，则同时在 `.env` 中提供：
   - `OPENAI_BASE_URL`
   - `OPENAI_API_KEY`
   - 或 provider 专属变量

对于“新机器直接复现”的目标，推荐优先采用：

- 项目根 `opencode.json` 作为 provider 定义源
- `.env` 作为 machine-local 运行配置源

这样新机器通常不需要手改 `~/.config/opencode/opencode.json`。

---

## 9. 目标 repo 下载规范

### 9.1 必须使用 `repo/clone_repos.py`

联网版目标 repo 下载入口必须是：

- [repo/clone_repos.py](/e:/AI/Agent/workflow/VulnVersion/repo/clone_repos.py)

禁止改用：

- `clone_all_repos.py`
- Dockerfile 里直接散写多条 `git clone`

### 9.2 默认行为

默认：

- 不下载任何目标 repo

原因：

1. 减少镜像体积
2. 减少启动时间
3. 用户通常只需要一个 repo 或少量 repo

### 9.3 支持的选择方式

应支持：

```bash
python repo/clone_repos.py --repos curl
python repo/clone_repos.py --repos curl,openssl,qemu
python repo/clone_repos.py --repos all
```

也建议支持环境变量：

```bash
VV_REPOS=curl,openssl
```

### 9.4 官方来源映射

必须使用以下来源，不得参考本地已有错误 remote：

| repo            | canonical URL                                                          |
| --------------- | ---------------------------------------------------------------------- |
| `FFmpeg`      | `https://git.ffmpeg.org/ffmpeg.git`                                  |
| `ImageMagick` | `https://github.com/ImageMagick/ImageMagick.git`                     |
| `curl`        | `https://github.com/curl/curl.git`                                   |
| `httpd`       | `https://github.com/apache/httpd.git`                                |
| `linux`       | `https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git` |
| `openjpeg`    | `https://github.com/uclouvain/openjpeg.git`                          |
| `openssl`     | `https://github.com/openssl/openssl.git`                             |
| `qemu`        | `https://gitlab.com/qemu-project/qemu.git`                           |
| `wireshark`   | `https://gitlab.com/wireshark/wireshark.git`                         |

如需 fallback，只能是明确声明过的官方/权威备选，不得随意新增。

---

## 10. repo 完整性要求

### 10.1 必须完整 clone

目标 repo 必须完整下载，不能丢历史、不能丢 tag。

明确要求：

1. 完整 clone
2. 完整历史
3. 完整 tag refs
4. clone 后显式 `fetch --tags`

### 10.2 明确禁止

禁止：

- `--depth 1`
- partial clone
- `--no-tags`

### 10.3 `required_paths` 的含义

`required_paths` **只是校验哨兵**，不是下载范围。

它的作用只是：

- 判断 repo 是否下载正确
- 判断 repo 是否可能不完整

不是说只需要这些 path 即可。

### 10.4 `required_tags` 的含义

`required_tags` 的作用是：

- 校验该 repo 是否具备数据集所依赖的关键历史 tag

这也不是说只下载这些 tag。
**真正要求是全部 tag refs 都要拿到。**

### 10.5 推荐校验逻辑

联网版 `clone_repos.py` 应至少执行以下校验：

1. `git remote get-url origin`
2. `git fetch --force --tags origin`
3. `git ls-remote --tags origin`
4. `git tag -l`
5. `git cat-file -e HEAD:<path>` 或同等路径检查

至少应保证：

1. origin URL 命中 canonical / fallback 允许集
2. 本地 tag 集不是残缺集
3. 命中预设 `required_tags`
4. 命中预设 `required_paths`

---

## 11. NVD 抓取与 `nvd_crawler.py` 规范

### 11.1 Step1 正确流程

主流程在需要 `cve_desc` 时，正确逻辑应为：

1. 先查：

```text
DataSet/BaseData_nvd.json
```

2. 如果该 `CVE-ID` 不存在，则调用：

```text
DataSet/nvd_crawler.py
```

3. crawler 从：

```text
https://nvd.nist.gov/vuln/detail/<CVE-ID>
```

抓取信息

4. 然后把结果**增量写回**：

```text
DataSet/BaseData_nvd.json
```

5. 主流程再从这个缓存文件读取 description/source 信息，继续 patch 分析

### 11.2 设计要求

`nvd_crawler.py` 必须满足：

1. 使用系统 `curl`
2. 不能写死 `curl.exe`
3. 默认读写项目相对路径
4. 支持单个 `--cve-id`
5. 写回 `BaseData_nvd.json` 时做**增量合并更新**

### 11.3 不允许的实现

不允许：

1. 纯 `httpx` / `requests` 抓 NVD 详情页作为最终设计方案
2. 写死 `curl.exe`
3. 重写 `BaseData_nvd.json` 为只含一个 CVE 的新文件

### 11.4 Dockerfile 层要求

因此联网版 Dockerfile 必须：

1. 安装 `curl`
2. 不再依赖 `curl.exe` 假名兼容层，前提是源码按本规范修正

如果下一步编写 Dockerfile 时源码仍未修到这个标准，可以临时保留兼容层，但**不建议作为最终设计**。

---

## 12. 必须进入镜像的内容

联网版镜像中，必须保留：

### 主程序

- `main.py`
- `opencode.json`
- `vuln_config.json`
- `requirements.txt`
- `environment.yml`
- `start_opencode.sh`
- `.opencode/`
- `vulnversion/`

### 数据

- `DataSet/BaseDataTest.json`
- `DataSet/BaseDataSet.json`
- `DataSet/BaseDataSet_30.json`
- `DataSet/BaseData_nvd.json`
- `DataSet/nvd_crawler.py`

### 目录

- `repo/`
- `Result/`

### Repo 下载脚本

- `repo/clone_repos.py`

---

## 13. 不应进入镜像的内容

联网版镜像中，以下内容不应作为运行依赖保留：

1. `DataSet/CveDetail/`
2. `docs/`
3. `tests/`
4. `Result/*` 旧结果
5. `Result_step12/`
6. `Result-5.2/`
7. `Result-old/`
8. `Replication/`
9. `SystemDesign/`
10. 宿主机本地历史实验产物

如果源码 clone 后天然带上了这些目录，可以在镜像构建后适度清理，以减小体积。

---

## 14. 构建时建议的系统依赖

建议联网版 Dockerfile 至少安装：

- Conda 发行版本体
- `git`
- `curl`
- `ca-certificates`
- `bash`
- `tini`

其余：

- `python`
- `nodejs`
- `npm`
- `ripgrep`

应优先通过 Conda 环境安装，而不是散落为 Docker 系统层依赖。

如果后续脚本需要更多 Git/调试工具，可再增加，但上面这些是最低推荐集。

---

## 15. 容器内工作目录与运行方式

### 15.1 工作目录

必须固定：

```dockerfile
WORKDIR /root/VulnVersion
```

### 15.2 相对路径运行

运行时统一用相对路径：

```bash
python main.py --dataset DataSet/BaseDataTest.json
```

### 15.3 标准运行顺序

联网版建议的运行顺序：

1. 根据用户需要下载 repo
2. 启动 OpenCode
3. 运行 `main.py`

也就是：

```bash
python repo/clone_repos.py --repos curl
./start_opencode.sh
python main.py --dataset DataSet/BaseDataTest.json --no-watch
```

---

## 16. 环境变量规范

联网版应支持以下环境变量：

### 16.1 主项目源码

- `VV_GIT_URL`
- `VV_GIT_REF`

### 16.2 repo 下载

- `VV_REPOS`

### 16.3 OpenCode / Provider

- `OPENAI_BASE_URL`
- `OPENAI_API_KEY`
- `OPENAI_MODEL`
- `OPENCODE_PROVIDER_ID`
- `OPENCODE_MODEL_ID`
- `OPENCODE_HOST`
- `OPENCODE_PORT`
- `CONDA_ENV_NAME`

如采用自定义 provider env 驱动设计，也可额外支持：

- `MINIMAXLOCAL_BASE_URL`
- `MINIMAXLOCAL_API_KEY`
- `XIAOAIPLUS_BASE_URL`
- `XIAOAIPLUS_API_KEY`
- `C402_BASE_URL`
- `C402_API_KEY`

并且应明确：

- 新机器不应把 `~/.config/opencode/opencode.json` 作为 VulnVersion 运行前提
- 项目应优先依赖项目根 `opencode.json`

### 16.4 可选

- `VV_DATASET`

例如：

```bash
VV_REPOS=curl
VV_DATASET=DataSet/BaseDataTest.json
```

---

## 17. 建议的启动脚本职责划分

### 17.1 `docker-entrypoint.sh`

职责建议：

1. 准备运行目录
2. 可选执行 repo 下载
3. 检查 `.env` / provider 配置
4. 不直接强耦合到单一模型厂商

### 17.2 `run_vulnversion.sh`

职责建议：

1. 启动 OpenCode
2. 等待 OpenCode 健康检查通过
3. 执行：

```bash
python main.py --dataset ...
```

这样能保持和离线版一致的使用体验。

---

## 18. Dockerfile 编写时的明确实现建议

编写联网版 Dockerfile 时，建议按以下阶段组织：

### 阶段 A：基础系统层

安装：

- Ubuntu 基础系统依赖
- curl
- git
- ca-certificates
- bash
- tini
- Miniforge / Miniconda / Mambaforge

### 阶段 B：Conda 环境与 OpenCode 层

1. 使用 `environment.yml` 创建 `VulnVersion` Conda 环境
2. 在 Conda 环境内确保：
   - `python`
   - `git`
   - `curl`
   - `nodejs`
   - `npm`
   - `ripgrep`
3. 全局安装 `opencode-ai@1.2.26`
4. 如需要，安装项目内 `.opencode` 依赖

### 阶段 C：获取主项目源码

1. clone `VV_GIT_URL`
2. checkout `VV_GIT_REF`
3. 记录实际 commit SHA

### 阶段 D：镜像清理与运行文件准备

1. 创建 `repo/`
2. 创建 `Result/`
3. 赋予 `start_opencode.sh` 执行位
4. 部署：
   - `repo/clone_repos.py`
   - `docker-entrypoint.sh`
   - `run_vulnversion.sh`

---

## 19. 验收清单

Dockerfile 编写完成后，至少应满足以下验收条件：

### 构建验收

1. 可成功 build
2. build 时能 clone `https://github.com/Jimi-Lab/VulnVersion.git`
3. 可通过 `VV_GIT_REF` 指定 ref
4. 镜像内存在 `/root/VulnVersion`
5. 可成功创建 `VulnVersion` Conda 环境

### 运行验收

1. `conda run -n VulnVersion python --version` 为 `3.11.x`
2. `conda run -n VulnVersion opencode --help` 可运行
3. `conda run -n VulnVersion git --version` 可运行
4. `conda run -n VulnVersion curl --version` 可运行
5. `conda run -n VulnVersion python repo/clone_repos.py --list` 可运行
6. `conda run -n VulnVersion python repo/clone_repos.py` 默认不下载 repo
7. `conda run -n VulnVersion python main.py --help` 可运行

### 语义验收

1. `repo/clone_repos.py` 不使用猜 URL 逻辑
2. repo 下载拉取完整历史与全部 tag
3. `BaseData_nvd.json` 在镜像中存在
4. OpenCode/provider 不依赖硬编码真实密钥
5. 默认运行路径为相对项目根

---

## 20. 给下一步 Codex 的直接执行指令

下一步编写联网版 Dockerfile 时，必须按以下原则执行：

1. 以本文件为主规格
2. 不要再猜 repo 下载链接
3. 不要再把联网版写成“只适合本机调试”的容器
4. 必须引入 Conda 作为 Docker 主环境
5. 必须让 Dockerfile、entrypoint、run 脚本三者职责清晰
6. 必须为后续固定 commit/tag 复现留出接口
7. 对 `nvd_crawler.py` 的预期是：使用 `curl`、增量更新 `BaseData_nvd.json`、默认相对路径

如果 Dockerfile 编写过程中需要在“当前代码现状”和“本规格目标”之间做取舍，应优先保证：

1. 复现性
2. 多机器部署稳定性
3. repo 来源正确性
4. tag/history 完整性
5. provider 配置可注入性

---

## 21. 最终一句话总结

联网版 Dockerfile 的正确目标是：

> 用 GitHub 固定 ref 获取 `VulnVersion` 主项目，用 Conda 统一管理 Python/Node/git/curl/ripgrep 环境，用 `clone_repos.py` 按需从官方来源完整拉取目标 repo，并通过 OpenCode + env 注入 provider 构建一个可复现、可迁移、可多机器部署的 Ubuntu 镜像。
