# VulnVersion GitHub 源码仓维护方案

## 1. 目标

本文件用于明确 `VulnVersion` 面向 GitHub 私有仓库维护时的边界、目录保留规则、配置策略与后续 push 规范。

当前目标不是“完整备份本地工作区”，而是整理出一个**面向复现的源码仓**，满足以下要求：

1. 新机器 `git clone` 后可直接用于联网版 Docker 构建与本地复现。
2. 仓库内保留核心源码、Docker 方案、数据集索引、skills、配置模板。
3. 不上传本地实验结果、下载好的目标 repo、敏感密钥、缓存和宿主机噪声文件。
4. 后续如对 `VulnVersion` 做改进，只维护 `main` 分支即可。

---

## 2. 首次建立仓库时的前提

以下内容描述的是首次建立 Git 仓库之前的初始前提：

1. 本地 `VulnVersion` **还不是 Git 仓库**。
2. 当前没有 `origin`。
3. 当前没有任何历史提交需要保留。
4. 这次要上传的是一个**面向复现的源码仓**，不是完整实验工区镜像。
5. 默认仅使用 `main` 分支。

这意味着可以直接从一个干净的初始化状态开始设计仓库结构，不需要迁移旧 Git 历史。

---

## 3. GitHub 仓库的推荐根目录

## 3.1 结论

后续初始化 Git、添加 `.gitignore`、首次 `git add/commit/push`，都应在：

```text
E:\AI\Agent\workflow\VulnVersion
```

这个路径下进行。

## 3.2 原因

原因很直接：

1. 这里是 `main.py`、`vulnversion/`、`DataSet/`、`.opencode/`、`opencode.json`、`environment.yml` 所在的**真实项目根**。
2. Docker 设计已经约定容器内项目根为 `/root/VulnVersion`。
3. 如果从 `E:\AI\Agent\workflow` 开始初始化并 push，那么远端仓库根路径会变成：

```text
VulnVersion/...
docker/...
SystemDesign/...
```

这会让 Docker 和本地复现都多出一层路径，不符合“拉下来即可直接当源码根使用”的要求。

## 3.3 路径要求

远端 GitHub 仓库在 clone 后，应直接得到如下根结构：

```text
VulnVersion-repo-root/
  main.py
  vulnversion/
  DataSet/
  .opencode/
  opencode.json
  environment.yml
  requirements.txt
  start_opencode.sh
  start_opencode.cmd
  repo/
  Result/
  docker/      
```

也就是说，**GitHub 仓库根应等价于当前本地 `E:\AI\Agent\workflow\VulnVersion` 的内容层级**，而不是它的父目录。

---

## 4. 本次源码仓的保留目标

本次源码仓应保留以下类型内容：

1. 源码
2. Docker 方案
3. 数据集索引
4. OpenCode skills / tools
5. 配置模板
6. 运行入口
7. 必要说明文档

注意：这里的“文档”是指**运行和复现所需的文档**，不是所有研究过程文档都要带上。

---

## 5. 应该保留到 GitHub 的内容

建议保留以下目录或文件：

### 5.1 核心源码

- `main.py`
- `vulnversion/`

### 5.2 OpenCode 项目资产

- `.opencode/skills/`
- `.opencode/tools/`
- `.opencode/package.json`
- `.opencode/bun.lock`
- `.opencode/.gitignore`

说明：

- `.opencode/opencode.json` 已废弃，不应再保留
- 项目级 OpenCode provider 配置已改为项目根 `opencode.json`

### 5.3 OpenCode / LLM 配置

- `opencode.json`
- `.env.example`
- `vuln_config.json`

### 5.4 环境与运行入口

- `environment.yml`
- `requirements.txt`
- `start_opencode.sh`
- `start_opencode.cmd`

### 5.5 数据集索引与运行期辅助数据

- `DataSet/BaseDataSet.json`
- `DataSet/BaseDataSet_30.json`
- `DataSet/BaseDataTest.json`
- `DataSet/BaseData_nvd.json`
- `DataSet/CVE_ID.txt`
- `DataSet/nvd_crawler.py`

### 5.6 repo 相关脚本与占位目录

- `repo/clone_repos.py`
- `repo/`

说明：

- `repo/` 目录本身应保留
- 但目录下下载好的目标仓库不能 push

### 5.7 结果目录

- `Result/`

说明：

- 只保留目录本身
- 目录下内容不 push
- 后续应通过 `.gitkeep` 或等价空目录保留方式维持目录存在

### 5.8 复现相关文档

应保留与运行、环境、Docker、配置直接相关的说明，例如：

- `readme.md`
- `readme_original_spec.md`（如果你认为它仍有复现参考价值）

如后续要把 Docker 规范也纳入源码仓，则应把：

- `docker/`

并入源码仓或复制到仓库内对应路径。

---

## 6. 不应 push 到 GitHub 的内容

### 6.1 敏感信息

- `.env`
- 任何真实 API key
- 任何宿主机私有 endpoint 凭据
- `~/.config/opencode/opencode.json` 的本机内容

### 6.2 本地下载的目标仓库

- `repo/*` 中真实下载的 FFmpeg / curl / openssl / linux / qemu 等仓库

只保留：

- `repo/clone_repos.py`
- 必要的空目录占位

### 6.3 实验输出与历史结果

- `Result/*`
- `Result-5.2/`
- `Result-BeforeEdit/`
- `Result-old/`
- `Result_step12/`

### 6.4 本地缓存与环境噪声

- `node_modules/`
- `__pycache__/`
- `.pytest_cache/`
- `.mypy_cache/`
- `.ruff_cache/`
- `.coverage`
- `Thumbs.db`
- `.DS_Store`

### 6.5 当前不保留的目录

根据本次要求，以下目录不保留到面向复现的源码仓：

- `tests/`
- `docs/`

这两个目录目前对“最终 GitHub 复现源码仓”不是必须项。

---

## 7. 关于 `tests/` 与 `docs/` 的处理

这里要明确一下边界。

你给出的约束是：

1. 保留源码、Docker 方案、数据集索引、skills、配置模板、文档
2. 但当前阶段 `tests/` 和 `docs/` 无需保留

因此这里建议做如下解释：

- `VulnVersion/docs/`：不进入 GitHub 复现源码仓
- `VulnVersion/tests/`：不进入 GitHub 复现源码仓
- 但**与部署直接相关的文档**仍然要保留，例如：
  - `readme.md`
  - Docker 相关说明
  - 配置模板说明

也就是说，这里的“文档”是**运行/部署/复现文档**，不是全部研究文档。

---

## 8. Docker 方案在源码仓中的要求

因为本次目标明确包含“面向复现”和“多机器部署”，所以 GitHub 源码仓中应保留 Docker 方案。

1. 保留联网版 Docker 规范
2. 保留离线版 Docker 规范
3. 保留后续 Dockerfile、entrypoint、run 脚本

如果当前 `docker/` 目录还在 `E:\AI\Agent\workflow\docker` 而不在 `VulnVersion` 内部，那么在真正 push 前需要做一个选择：

1. 将 `docker/` 目录迁入 `VulnVersion/`
2. 或将需要的 Docker 文档和构建文件复制进 `VulnVersion/docker/`

否则单独 clone `VulnVersion` 仓库后，Docker 方案会丢失。

这是后续 push 前必须处理的一项结构性问题。

---

## 9. LLM / OpenCode 配置说明

本次 GitHub 源码仓中必须把“如何接模型”说清楚。

## 9.1 当前配置分层

当前 VulnVersion 中，模型配置分为三层：

### A. 项目根 `opencode.json`

职责：

- 定义 OpenCode provider
- 定义 provider 使用的 OpenAI-compatible endpoint
- 定义 models

这是项目级配置源，应纳入 GitHub。

### B. 项目根 `.env`

职责：

- 为当前机器选择实际使用的 provider/model
- 注入密钥、endpoint、端口、环境名等 machine-local 参数

`.env` 不应纳入 GitHub，只保留 `.env.example`。

### C. `vuln_config.json`

职责：

- 告诉 VulnVersion Python 客户端如何访问 OpenCode 服务

当前默认是：

- `http://127.0.0.1:4096`

这个文件通常应纳入 GitHub。

## 9.2 使用 OpenCode 内建 provider 的方法

如果使用 OpenCode 已支持的内建 provider，通常：

1. 保持项目根 `opencode.json` 中已有对应 provider
2. 在 `.env` 中设置：
   - `OPENCODE_PROVIDER_ID`
   - `OPENCODE_MODEL_ID`
   - 以及需要的 key / endpoint 变量

示例：

```env
OPENCODE_PROVIDER_ID=openrouter
OPENCODE_MODEL_ID=openai/gpt-5.2
OPENAI_BASE_URL=https://openrouter.ai/api/v1
OPENAI_API_KEY=...
```

## 9.3 使用自定义 provider / 自定义模型的方法

如果要使用自定义 OpenAI-compatible endpoint：

1. 在项目根 `opencode.json` 中定义 provider
2. 在 `.env` 中设置：
   - `OPENCODE_PROVIDER_ID`
   - `OPENCODE_MODEL_ID`
3. 如果 provider 的 `baseURL` / `apiKey` 是 env 驱动，还需在 `.env` 中设置：
   - `OPENAI_BASE_URL`
   - `OPENAI_API_KEY`
     或 provider 专属变量

当前项目已明确不应再依赖：

- `.opencode/opencode.json`
- `~/.config/opencode/opencode.json`

也就是说，新机器上应尽量做到：

1. clone 仓库
2. 复制 `.env.example` 为 `.env`
3. 填入 provider/model 和密钥
4. 启动 `start_opencode.sh` / `start_opencode.cmd`

## 9.4 GitHub 上应保留什么

应保留：

- `opencode.json`
- `.env.example`
- 配置迁移说明（如需）

不应保留：

- `.env`
- 任何真实 key
- 任何宿主机私有全局配置

---

## 10. 结果目录的处理策略

本次要求是：

- `Result` 文件夹需要保留
- 文件夹下的内容无需 push

因此建议：

1. 保留 `Result/`
2. 在 `Result/` 下放一个：
   - `.gitkeep`
     或
   - `README.md`
3. `.gitignore` 中忽略 `Result/**`
4. 但显式保留：
   - `Result/.gitkeep`

这样仓库 clone 后目录结构正确，但不会把历史运行结果一起带上。

---

## 11. 推荐的 `.gitignore` 规则

后续在 `E:\AI\Agent\workflow\VulnVersion\.gitignore` 中，至少应包含：

```gitignore
# secrets
.env

# Python cache
__pycache__/
.pytest_cache/
.mypy_cache/
.ruff_cache/
.coverage

# Node
node_modules/
.opencode/node_modules/

# downloaded target repos
repo/*
!repo/clone_repos.py
!repo/.gitkeep

# results
Result/**
!Result/.gitkeep
Result-5.2/
Result-BeforeEdit/
Result-old/
Result_step12/

# docs/tests excluded from repro source repo
docs/
tests/

# dataset details not required
DataSet/CveDetail/

# OS noise
Thumbs.db
.DS_Store
```

如果未来还要保留 `docs/` 或 `tests/`，再单独调整。

---

## 12. 首次初始化与首次发布的具体命令

以下命令都必须在：

```text
E:\AI\Agent\workflow\VulnVersion
```

这个路径下执行。

### 12.1 首次初始化 Git

如果本地还没有初始化 Git，按下面顺序执行：

```powershell
cd E:\AI\Agent\workflow\VulnVersion
git init -b main
```

### 12.2 首次发布前检查

先确认应忽略的内容没有被纳入：

```powershell
cd E:\AI\Agent\workflow\VulnVersion
git status --short --ignored
git check-ignore -v .env
git check-ignore -v repo\ffmpeg
git check-ignore -v Result\some-output-file.json
```

说明：

- `git status --short --ignored` 用来同时看已纳入文件和被忽略文件
- `git check-ignore -v` 用来检查某个路径是否被 `.gitignore` 正确忽略

### 12.3 首次加入文件并提交

确认无误后执行：

```powershell
cd E:\AI\Agent\workflow\VulnVersion
git add .
git status --short
git commit -m "Initialize repro-ready VulnVersion source repository"
```

### 12.4 绑定 GitHub 远端

本项目当前远端仓库地址固定为：

```text
https://github.com/Jimi-Lab/VulnVersion.git
```

绑定命令：

```powershell
cd E:\AI\Agent\workflow\VulnVersion
git remote add origin https://github.com/Jimi-Lab/VulnVersion.git
git remote -v
```

### 12.5 Windows 上如遇 `dubious ownership`

如果 Git 提示：

```text
fatal: detected dubious ownership in repository ...
```

则执行：

```powershell
git config --global --add safe.directory E:/AI/Agent/workflow/VulnVersion
```

### 12.6 首次推送到 GitHub

```powershell
cd E:\AI\Agent\workflow\VulnVersion
git push -u origin main
```

首次推送完成后，后续本地 `main` 会自动跟踪远端 `origin/main`。

---

## 13. main 分支维护策略

当前你已经明确：

1. 直接使用 `main`
2. 后续若源码继续改进，直接更新 `main`

这个策略对于当前阶段是合理的。

建议规则：

1. `main` 只维护“可运行、可复现”的状态
2. 若某次实验对应一个稳定版本，建议打 tag
3. Dockerfile 和环境变更尽量与源码一起提交

---

## 14. 后续修改源码后的具体提交与推送命令

当你后续修改了 `VulnVersion` 源码，希望继续推送到 GitHub 时，直接在项目根执行以下命令。

### 14.1 日常更新的标准流程

```powershell
cd E:\AI\Agent\workflow\VulnVersion
git status --short
git add .
git status --short
git commit -m "Describe your change here"
git push origin main
```

### 14.2 更稳妥的提交流程

如果你想先看清楚哪些文件变了，再提交：

```powershell
cd E:\AI\Agent\workflow\VulnVersion
git status
git diff
git add main.py
git add vulnversion
git add opencode.json
git add environment.yml
git status --short
git commit -m "Refine VulnVersion implementation"
git push origin main
```

### 14.3 修改 Docker 相关文件后的推送命令

```powershell
cd E:\AI\Agent\workflow\VulnVersion
git status --short
git add docker
git add .env.example
git add environment.yml
git add requirements.txt
git commit -m "Update Docker deployment configuration"
git push origin main
```

### 14.4 修改 OpenCode / 模型配置模板后的推送命令

```powershell
cd E:\AI\Agent\workflow\VulnVersion
git status --short
git add opencode.json
git add .env.example
git add vuln_config.json
git add start_opencode.sh
git add start_opencode.cmd
git add start_opencode.ps1
git commit -m "Update OpenCode configuration templates"
git push origin main
```

### 14.5 推送前的建议检查命令

```powershell
cd E:\AI\Agent\workflow\VulnVersion
git status --short --ignored
git diff --staged
git remote -v
git branch -vv
```

### 14.6 查看最近提交记录

```powershell
cd E:\AI\Agent\workflow\VulnVersion
git log --oneline -n 10
```

### 14.7 如果误把不该提交的文件加入暂存区

例如误加入了结果文件或本地配置文件，可以先撤出暂存区：

```powershell
cd E:\AI\Agent\workflow\VulnVersion
git restore --staged .env
git restore --staged Result
git restore --staged repo
git status --short
```

---

## 15. 当前阶段的结论

### 15.1 结论一：应该从哪个路径开始 push

应从：

```text
E:\AI\Agent\workflow\VulnVersion
```

开始初始化 Git 和后续 push。

### 15.2 结论二：当前 GitHub 仓库应是什么性质

当前 GitHub 仓库应是：

- 一个**面向复现的源码仓**

而不是：

- 全工作区仓库
- 实验结果仓库
- 本地下载 repo 仓库

### 15.3 结论三：在首次 push 前的关键准备项

首次 push 前，至少还要完成：

1. 根目录 `.gitignore`
2. `repo/` 与 `Result/` 的占位文件
3. Docker 相关目录是否并入 `VulnVersion` 的最终决策
4. `.env` 与 key 的彻底排除

---

## 16. 当前仓库的已执行状态

截至当前，已实际完成以下操作：

```powershell
cd E:\AI\Agent\workflow\VulnVersion
git init -b main
git add .
git commit -m "Initialize repro-ready VulnVersion source repository"
git remote add origin https://github.com/Jimi-Lab/VulnVersion.git
git config --global --add safe.directory E:/AI/Agent/workflow/VulnVersion
git push -u origin main
```

因此，后续你通常不再需要重复初始化和绑定远端，只需要走“修改后提交并推送”的日常流程即可。

---

## 17. 下一步建议

下一步最合理的动作是：

1. 修改源码后先执行 `git status --short`
2. 再执行 `git add` / `git commit`
3. 最后执行 `git push origin main`
4. 若是关键复现实验节点，建议额外打 tag

本文件写完后，可以直接作为后续 Git 初始化与首次 push 的执行依据。
