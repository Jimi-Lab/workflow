# VulnVersion 联网版 Docker 设计说明

本文件用于指导下一步生成 `VulnVersion` 的**联网版本 Dockerfile**。

参考基础文档：

- [docker.md](/e:/AI/Agent/workflow/docker/docker.md)
- [readme.md](/e:/AI/Agent/workflow/docker/readme.md)

更新时间：`2026-04-17`

---

## 1. 目标

联网版 Docker 的定位与离线版不同。

它的目标是：

1. 允许在可联网环境中直接构建并运行 `VulnVersion`
2. `VulnVersion` 主项目源码在镜像构建时通过 GitHub 获取
3. 目标待测 repo 不默认下载，减少镜像和容器空间占用
4. 用户可在容器内按需下载 `1` 个、`N` 个或全部待测 repo
5. 保持与离线版一致的运行接口、OpenCode 接口、数据集布局和结果目录布局
6. 联网版本身也要支持复现与多机器部署，而不只是“本机调试容器”

---

## 2. 与离线版的关系

联网版与离线版不是互斥，而是两套不同的交付模式：

### 离线版 `docker/NoInternet`

- 适用于跨机器、无外网复现
- 主项目源码和 repo bundle 一起进入镜像
- 运行时不依赖外网

### 联网版 `docker/Internet`

- 适用于开发、调试、在线实验
- 同样适用于多机器部署，只是目标环境允许联网
- 主项目源码在构建镜像时通过 GitHub clone
- 目标待测 repo 在容器内按需下载
- 默认不下载任何待测 repo

---

## 3. 关于后续继续修改 VulnVersion 主代码

这是当前最需要先说明清楚的一点。

### 结论

**会影响 Docker 部署。**

原因很简单：

- Docker 镜像里保存的是某一个时刻的 `VulnVersion` 代码快照
- 你本地后续继续改 `VulnVersion`，镜像里的代码不会自动同步更新

### 需要重新做什么

分两种情况：

#### 情况 A：只改了 `VulnVersion` 主代码

例如你修改了：

- `main.py`
- `vulnversion/`
- `.opencode/`
- `requirements.txt`
- `start_opencode.sh`
- `vuln_config.json`

这时需要：

1. 重新构建 Docker 镜像

通常**不需要**重新生成 repo bundle。

也就是说：

- 需要重新走 Docker build
- 不需要重新生成 `docker/NoInternet/repo-bundles/*.bundle`

除非你连 repo 离线资产策略也改了。

#### 情况 B：你改了离线版 Docker 逻辑本身

例如你修改了：

- `docker/NoInternet/Dockerfile`
- `docker/NoInternet/docker-entrypoint.sh`
- `docker/NoInternet/run_vulnversion.sh`
- `docker/NoInternet/opencode.offline.json`

这时同样需要重新构建离线镜像。

#### 情况 C：你改了 repo bundle 或其来源

例如：

- 更新了某个待测 repo 的缓存
- 修正了错误 repo 来源
- 想带入更多 tag/history

这时需要：

1. 重新生成对应 bundle
2. 再重新构建离线镜像

### 对 `docker/NoInternet` 的操作结论

如果只是继续优化 `VulnVersion` 代码：

- **要重新 build 镜像**
- **通常不用重新生成 bundle**
- **也不用把 `docker/NoInternet` 里的所有逻辑重新设计一遍**

---

## 4. 联网版主项目源码来源

联网版先固定主项目源码来源为：

```text
https://github.com/Jimi-Lab/VulnVersion.git
```

### 设计要求

下一步生成联网版 Dockerfile 时，必须支持：

1. clone 该 GitHub 仓库
2. 支持指定分支、tag 或 commit
3. 避免默认永远拉取最新 `main`

### 推荐参数

建议 Dockerfile 预留：

```dockerfile
ARG VV_GIT_URL=https://github.com/Jimi-Lab/VulnVersion.git
ARG VV_GIT_REF=main
```

然后在 build 阶段：

- clone `VV_GIT_URL`
- checkout `VV_GIT_REF`

### 为什么必须支持固定 ref

如果 Dockerfile 永远 clone 最新主分支：

- 今天构建和下周构建的镜像不一定一致
- 论文复现实验无法稳定复现

因此联网版也必须支持：

- 固定 tag
- 固定 commit
- 固定 release branch

### 对 `main` 的进一步约束

`VV_GIT_REF=main` 只能作为开发便利默认值，不能作为论文复现的最终约定。

对于真正的复现、多机器部署、对外分发，必须优先使用：

- 固定 commit
  或
- 固定 tag

建议下一步 Dockerfile 同时把实际构建的 ref 写入：

- image label
- 或 `/root/VulnVersion/.build_ref`

这样容器启动后可以直接确认镜像内源码版本。

---

## 5. 联网版 repo 下载策略

联网版不使用 bundle，而是在容器中按需下载待测 repo。

### 核心要求

1. 默认不下载任何待测 repo
2. 用户可以选择下载：
   - 单个 repo
   - 多个 repo
   - 全部 repo
3. clone URL 写死在容器内脚本中，不允许运行时猜 URL
4. clone 后必须做校验

### 目标脚本

下一步需要新增：

- [repo/clone_repos.py](/e:/AI/Agent/workflow/VulnVersion/repo/clone_repos.py)

该脚本会部署进联网版 Docker 镜像中。

### 推荐调用方式

```bash
python repo/clone_repos.py --repos curl
python repo/clone_repos.py --repos curl,openssl,qemu
python repo/clone_repos.py --repos all
```

也可以支持环境变量形式：

```bash
VV_REPOS=curl,openssl python repo/clone_repos.py
```

### 默认行为

默认：

- `--repos` 未指定时，不下载任何待测 repo

这样可以减少：

- 初始镜像体积
- 初次容器启动时间
- 磁盘空间占用

---

## 6. 为什么不能直接复用现有 `clone_all_repos.py`

当前文件：

- [repo/clone_all_repos.py](/e:/AI/Agent/workflow/VulnVersion/repo/clone_all_repos.py)

不能直接用于联网版 Docker，原因包括：

1. 脚本默认依赖外部 Windows 路径
2. URL 映射不完整
3. 存在错误映射
4. 存在 URL 猜测逻辑
5. 没有足够严格的 clone 后校验

因此下一步必须新写：

- `repo/clone_repos.py`

而不是继续修补 `clone_all_repos.py`

并且要特别强调：

- 你当前本地 `repo/` 里如果曾经用错过 GitHub 地址，这些历史错误**不能**被沿用到 Docker 设计中
- 联网版 Docker 必须只使用本说明文档中确认过的官方 / 权威 canonical URL
- 不允许“参考本地已有仓库 remote”来反推 Docker 里的下载地址

---

## 7. GitHub / GitLab / 原生 Git 仓库兼容性结论

你重点问到：

- `FFmpeg`
- `qemu`
- `wireshark`
- `linux`

这四个 repo 并不都来自 GitHub。

### 结论

**VulnVersion 兼容的核心对象是“本地 Git 仓库”，不是 GitHub 本身。**

只要最终落到容器内的是一个**完整的本地 Git 工作树仓库**：

- `repo/<repo_name>/.git`

并且这个仓库包含完整：

- commits
- tags
- refs
- objects
- blame/log 所需历史

那么 VulnVersion 的 Git 能力就可以正常工作。

### 也就是说

以下来源类型在原则上都兼容：

1. GitHub
2. GitLab
3. 官方原生 Git 服务器

VulnVersion 当前依赖的是本地 Git 命令，例如：

- `git show`
- `git grep`
- `git log`
- `git blame`
- `git merge-base`
- `git rev-list --ancestry-path`
- `git log -S`
- `git log -G`
- `git log -L`

这些操作并不关心仓库最初来自哪种 forge。

### 真正的风险不在 forge 类型，而在以下问题

1. clone 了错误仓库
2. clone 了 mirror，但历史或 tag 不完整
3. 使用了 shallow clone
4. 没有拉取 tag
5. clone 后未校验 repo 身份

### 因此必须坚持的规则

联网版 `clone_repos.py` 必须：

1. 明确 repo 名到 URL 的固定映射
2. 禁止 URL 猜测
3. 禁止 `--depth 1`
4. 必须将目标repo完整下载，不要有遗漏
5. clone 后校验 tag、关键路径、remote URL

### 关于“能不能彻底兼容”

更严格地说：

- **GitHub / GitLab / git 协议本身不是问题**
- **正确性依赖于下载到的本地 repo 是否完整且正确**

所以不能说“因为用了 GitLab 就一定完全没问题”，真正应该说的是：

> 只要联网版脚本从经过校验的官方/权威 URL 拉取完整仓库，并做 clone 后校验，VulnVersion 就可以兼容这些来源。

---

## 8. 联网版待测 repo 的固定来源

联网版 `repo/clone_repos.py` 必须内置固定映射。

建议沿用 `docker.md` 中确认过的来源：

| repo            | clone URL                                                              | 说明                |
| --------------- | ---------------------------------------------------------------------- | ------------------- |
| `FFmpeg`      | `https://git.ffmpeg.org/ffmpeg.git`                                  | FFmpeg 官方主 Git   |
| `ImageMagick` | `https://github.com/ImageMagick/ImageMagick.git`                     | 官方权威仓库        |
| `curl`        | `https://github.com/curl/curl.git`                                   | 官方仓库            |
| `httpd`       | `https://github.com/apache/httpd.git`                                | Apache 官方公开镜像 |
| `linux`       | `https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git` | 官方主线            |
| `openjpeg`    | `https://github.com/uclouvain/openjpeg.git`                          | 官方仓库            |
| `openssl`     | `https://github.com/openssl/openssl.git`                             | 官方公开仓库        |
| `qemu`        | `https://gitlab.com/qemu-project/qemu.git`                           | 官方 GitLab         |
| `wireshark`   | `https://gitlab.com/wireshark/wireshark.git`                         | 官方 GitLab         |

这里的设计目标不是“能 clone 下来就行”，而是：

- 必须使用正确的官方来源
- 必须下载完整仓库
- 必须完整拿到全部 tag 集

当前实现中至少应固化：

- `canonical_url`
- 可选 `fallback_urls`
- `required_tags`
- `required_paths`

### `required_paths` 的真实含义

这里的 `required_paths` **不是说只需要这些路径**。

它们只是：

- clone 后的校验哨兵
- 用来确认“下到的 repo 的确是目标项目，而不是错误仓库或不完整仓库”

也就是说：

- repo 仍然必须完整下载
- history 仍然必须完整下载
- tags 仍然必须完整下载
- `required_paths` 只是验收检查项之一

---

## 9. 联网版 clone 后必须做的校验

下载成功不等于 repo 正确。

下一步 `repo/clone_repos.py` 至少要做：

### 校验 1：origin URL

```bash
git remote get-url origin
```

必须命中允许列表。

### 校验 2：tag 完整性

```bash
git tag -l
```

这里不能只做“tag 非空”这种弱校验。

必须满足两层要求：

1. clone / fetch 过程必须显式拉取**全部 tag refs**
2. 校验时必须确认本地 tag 集与远端 tag 集一致，或至少命中预设 `required_tags`

推荐做法：

```bash
git fetch --force --tags origin
git ls-remote --tags origin
git tag -l
```

然后比较：

- 远端 tag 列表
- 本地 tag 列表

至少要确保：

- 不是 shallow/partial clone
- 没有 `--no-tags`
- 不是“只拿到少数 tag”
- 必须包含该 repo 在数据集中实际需要的关键历史 tag

### 校验 3：关键路径存在

例如：

```bash
git cat-file -e <ref>:<path>
git ls-tree -r --name-only <ref>
```

必须命中 repo 的关键目录或标志性文件。

### 校验 4：禁止浅克隆

clone 必须是完整历史。

不允许：

- `--depth 1`
- partial clone
- `--no-tags`

否则会直接破坏：

- `git blame`
- `git log -L`
- `git log -S/-G`
- tag 历史分析

---

## 10. Python / Node 环境管理

这是联网版 Docker 里必须先统一的点。

### 结论

**Docker 中不建议引入 Conda 作为主环境管理器。**

联网版与离线版都建议采用：

- Ubuntu 系统 Python 3.11
- `python -m venv` 或镜像内单 Python 环境
- `requirements.txt` 作为 Python 依赖单一事实来源

### 为什么不建议在 Docker 中主用 Conda

虽然项目里存在：

- [environment.yml](/e:/AI/Agent/workflow/VulnVersion/environment.yml)

但这个文件本质上只是一个很薄的包装：

- 指定 `python=3.11`
- 补充 `git`
- 最终 Python 包仍然来自 `pip`

而真正的 Python 依赖清单是：

- [requirements.txt](/e:/AI/Agent/workflow/VulnVersion/requirements.txt)

因此在 Docker 中如果再引入 Conda，会带来：

1. 镜像体积增大
2. 构建更慢
3. 额外的环境层级复杂度
4. 与当前项目真实依赖源不一致

### Docker 中推荐的 Python 管理方式

下一步 Dockerfile 应按以下方式设计：

1. 安装 Ubuntu 自带或系统包提供的 Python 3.11
2. 使用 `requirements.txt` 安装 Python 依赖
3. 不把 `environment.yml` 作为 Docker 里唯一环境构建入口

### `environment.yml` 的定位

这个文件建议保留，但定位应该是：

- 本地开发便利文件
- 给读者展示项目期望 Python 版本
- 非 Docker 构建主入口

### Node / npm 的管理方式

OpenCode 相关 Node 依赖仍然通过：

- `npm i -g opencode-ai`

以及项目自己的：

- `package.json`
- `package-lock.json`

来管理。

如果下一步 Dockerfile 需要安装项目级 Node 依赖，推荐优先使用：

```bash
npm ci
```

而不是 `npm install`，以保证构建更可复现。

---

## 11. 联网版镜像内必须保留的运行能力

即使是联网版，也不能只做“源码 clone + pip install”这么薄的一层。

下一步 Dockerfile 必须保证：

1. 安装 Python
2. 安装 git
3. 安装 Node.js / npm
4. 安装 OpenCode：

```bash
npm i -g opencode-ai
```

5. 安装 `curl`
6. 安装 Python 依赖
7. 给 `start_opencode.sh` 设置执行位

---

## 12. OpenCode / 本地模型 / 自定义 API provider 设计

联网版同样不能把真实 provider 和密钥写死到镜像里。

### 原则

1. 镜像中只保留模板配置
2. 真实模型地址与密钥由 `.env` 或环境变量注入
3. OpenCode 与 Python 侧模型配置必须一致

### 推荐支持的方式

1. `.env`
2. `docker run --env-file`
3. 直接传环境变量
4. 用户挂载自定义 `.opencode/opencode.json`

### 推荐最小环境变量集合

```bash
OPENAI_BASE_URL=http://127.0.0.1:8000/v1
OPENAI_API_KEY=dummy-or-real
OPENAI_MODEL=your-model-name
OPENCODE_PROVIDER_ID=local-openai
OPENCODE_MODEL_ID=your-model-name
```

### 额外说明

联网版“允许联网”并不等于必须依赖公网模型。

它同样应该支持：

1. 容器内访问宿主机本地部署模型
2. 容器内访问局域网模型服务
3. 访问任意 OpenAI-compatible API

因此 Dockerfile / 运行脚本不要把 provider 锁死成单一厂商。

---

## 13. NVD 缓存与 `nvd_crawler.py` 的运行逻辑

当前主流程对 CVE 描述的正确逻辑应当是：

1. 先从相对路径读取：

```text
DataSet/BaseData_nvd.json
```

2. 如果目标 `CVE-ID` 在缓存中不存在，自动调用：

```text
DataSet/nvd_crawler.py
```

3. `nvd_crawler.py` 从：

```text
https://nvd.nist.gov/vuln/detail/<CVE-ID>
```

抓取信息

4. 抓到后写回相对路径：

```text
DataSet/BaseData_nvd.json
```

5. 然后主流程继续从这个相对缓存里读取 description/source 信息，进入 patch 分析

### 当前设计要求

`nvd_crawler.py` 不应继续依赖：

- `curl.exe`
- Windows 路径

但这**不等于**应该改成纯 Python HTTP 客户端。

### 必须使用 `curl`

因为：

- `https://nvd.nist.gov/vuln/detail/` 对通用爬虫并不友好
- 直接用普通 Python HTTP 客户端更容易被封禁或返回异常页面

因此这里的设计要求应是：

- 必须调用系统里的 `curl`
- 但不能写死成 `curl.exe`

也就是说，目标实现应当是：

- Linux / Docker 中调用 `curl`
- Windows 中也应优先通过可解析的 `curl` 命令执行
- 不再把实现绑定到 `curl.exe` 这个 Windows 特定名字

### `BaseData_nvd.json` 的写回语义

写回：

```text
DataSet/BaseData_nvd.json
```

时，必须是：

- 读取现有 JSON
- 只更新当前 `CVE-ID` 对应记录
- 保留其他 CVE 记录

也就是**增量合并更新**，不是把整个文件重写成只含当前 CVE 的新文件。

### 目标行为

因此 `nvd_crawler.py` 的目标行为应是：

1. 默认读写项目相对路径
2. 支持单个 `--cve-id`
3. 使用 `curl` 下载 NVD 页面
4. 对 `BaseData_nvd.json` 做增量更新
5. 然后主流程继续从相对缓存读取该 CVE 信息

---

## 14. 数据集与运行时目录

联网版镜像中仍建议保留：

- `DataSet/BaseDataTest.json`
- `DataSet/BaseDataSet.json`
- `DataSet/BaseDataSet_30.json`
- `DataSet/BaseData_nvd.json`
- `DataSet/nvd_crawler.py`

并准备：

- `Result/`
- `repo/`

### 原因

1. `BaseData_nvd.json` 可以减少运行时抓取 NVD 的次数
2. 即使联网，CVE 描述也不应每次都重新抓
3. 结果目录必须存在，但不能预置旧结果

---

## 15. 联网版 Dockerfile 下一步必须实现的能力

下一步生成联网版 Dockerfile 时，必须实现：

1. 基于 Ubuntu 构建
2. 安装：
   - Python
   - git
   - curl
   - Node.js
   - npm
3. 全局安装 OpenCode：

```bash
npm i -g opencode-ai
```

4. clone `VulnVersion` 主项目：
   - 默认 `https://github.com/Jimi-Lab/VulnVersion.git`
   - 支持 `ARG VV_GIT_REF`
5. 设置：

```dockerfile
WORKDIR /root/VulnVersion
```

6. 保留：
   - `.opencode/`
   - `DataSet/BaseData_nvd.json`
   - `Result/`
   - `repo/`
7. 设置：
   - `chmod +x start_opencode.sh`
8. 部署：
   - `repo/clone_repos.py`
9. 默认不下载任何待测 repo
10. 允许用户按需触发 repo 下载
11. 使用 `requirements.txt` 管理 Python 依赖，而不是把 Conda 作为 Docker 主环境管理方式
12. `repo/clone_repos.py` 必须完整拉取远端全部 tag refs，而不是只验证“tag 非空”

---

## 16. 运行接口建议

联网版容器内建议保留与当前项目一致的运行方式：

```bash
python main.py --dataset DataSet/BaseDataTest.json
```

并额外支持：

```bash
python repo/clone_repos.py --repos curl
python repo/clone_repos.py --repos all
```

如果后续需要入口脚本，也应遵循：

1. 先下载所需 repo
2. 再启动 OpenCode
3. 最后运行 `main.py`

---

## 17. 这份 md 还建议补充什么

目前这份联网版设计说明已经足够指导下一步写 Dockerfile。

但如果你希望下一步生成 Dockerfile 更稳，还建议补充两类信息：

### 补充 1：你希望默认构建哪个 `VulnVersion` ref

例如：

- `main`
- 某个 release tag
- 某个固定 commit

如果你不指定，我下一步会先按：

```text
VV_GIT_REF=main
```

来设计，但会保留可覆盖参数。

### 补充 2：联网版是否需要提供“一键启动脚本”

也就是是否在 `docker/Internet` 下一步同步生成：

- `docker-entrypoint.sh`
- `run_vulnversion.sh`

如果不特别说明，我建议：

- 仍然提供这两个脚本

这样联网版和离线版的使用体验更一致。

---

## 18. 当前设计结论

针对你这次提出的 5 个问题，最终结论是：

1. 后续你继续修改 `VulnVersion` 主代码，会影响 Docker 镜像内容；需要重新 build 镜像，但通常不需要重新生成离线 repo bundle。
2. `FFmpeg/qemu/wireshark/linux` 使用 GitHub 以外的官方 Git/GitLab 来源没有本质问题；VulnVersion 依赖的是本地完整 Git 仓库，而不是某个 forge 品牌本身。真正必须保证的是 repo 来源正确、历史完整、clone 后有校验。
3. 联网版 Docker 也应服务于复现和多机器部署，不是一次性的本机调试容器。
4. Docker 中不建议主用 Conda；应使用 Python 3.11 + `requirements.txt` 管理 Python 依赖，`environment.yml` 保留为本地开发便利层。
5. 联网版 Docker 应与离线版分离设计：主项目源码从 `https://github.com/Jimi-Lab/VulnVersion.git` 获取，待测 repo 通过新的 `repo/clone_repos.py` 按需下载，默认不下载任何 repo；真正复现时不应直接依赖可变的 `main`，而应固定 commit 或 tag。
