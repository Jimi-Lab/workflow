# VulnVersion Docker 复现实验环境设计

本文件用于指导下一步生成 `VulnVersion` 的 Dockerfile，以及后续的 Docker 版 repo 初始化脚本。

参考基础文档：

- [readme.md](/e:/AI/Agent/workflow/docker/readme.md)

更新时间：`2026-04-16`

---

## 1. 设计目标

这次 Docker 设计的目标，不是“在当前 Windows 目录里临时跑一个容器”，而是：

1. 生成一个可以移植到其他 Ubuntu / 虚拟机环境的**复现实验镜像**。
2. 目标环境即使**不能访问外网**，也可以直接加载并运行。
3. 不依赖宿主机绑定挂载 Windows 本地源码。
4. 目标待测 repo 必须来自**正确的上游源码仓库**，不能依赖猜测 URL。
5. OpenCode 必须支持：
   - 本地部署模型
   - 自定义 OpenAI-compatible API
   - 用户自定义 provider 配置
6. `DataSet/BaseData_nvd.json` 必须进入镜像，方便实验复现。

---

## 2. 交付模式：不要把“构建镜像”和“移植运行”混为一谈

这里必须区分两个阶段：

### 阶段 A：构建镜像

构建镜像时，仍然可以使用本地源码作为 build context。

这不影响可移植性，因为：

- `COPY` 是**构建时行为**
- 目标环境不需要再拥有源码
- 目标环境只需要拿到已经构建好的镜像

### 阶段 B：移植运行

真正用于复现实验的交付物，应该是：

- 一个已经构建好的 Docker image
- 通过 `docker save` 导出为 tar 包
- 在目标 Ubuntu / VM 上通过 `docker load` 导入

也就是：

```bash
docker save vulnversion-offline:TAG | gzip > vulnversion-offline_TAG.tar.gz
docker load -i vulnversion-offline_TAG.tar.gz
```

### 结论

如果你的目标是：

> “移植到新的 Ubuntu / 虚拟机中可以直接启动，且无需访问外网”

那么推荐方案不是：

- 目标环境里再 `git clone` 主项目源码

而是：

- **在联网构建机上先构建好完整镜像**
- **将镜像打包后分发**

因此：

- `Dockerfile` 内部不需要依赖目标环境再去 `git clone VulnVersion` 主项目
- 目标环境也不需要挂载 Windows 本地源码

---

## 3. 主项目源码如何进入镜像

### 推荐方案

继续使用：

`本地 build context + 白名单 COPY`

但注意这里的含义是：

- 仅用于**构建镜像**
- 不作为目标实验环境对源码的依赖

### 不推荐方案

不建议把 `VulnVersion` 主项目作为“必须在线 clone 的仓库”写进 Dockerfile。

原因：

1. 目标机可能无法联网
2. GitHub / Gitee / GitLab 地址可能变化
3. 私有改动未必已经推送
4. 无法保证目标机拿到的就是你论文复现时的那一版源码

### 最终建议

主项目源码的复现交付方式应是：

1. 在构建机中固定一个 `VulnVersion` 提交版本
2. 用该版本构建镜像
3. 将镜像本身作为复现实验交付物

而不是要求目标机再去拿源码。

---

## 4. 容器内项目根目录

容器内固定项目根目录为：

```text
/root/VulnVersion
```

注意：

- 文档里可以写 `~/VulnVersion`
- 但 Dockerfile 中必须使用绝对路径

```dockerfile
WORKDIR /root/VulnVersion
```

---

## 5. 运行方式

容器内统一使用相对路径：

```bash
python main.py --dataset DataSet/BaseDataTest.json
```

这条约束继续保留。

---

## 6. repo 处理策略：不能继续依赖现有 `clone_all_repos.py`

当前文件：

- [repo/clone_all_repos.py](/e:/AI/Agent/workflow/VulnVersion/repo/clone_all_repos.py)

不能直接作为 Docker 版 repo 初始化脚本使用，原因已经非常明确：

1. 默认 dataset 路径写死到外部 Windows 目录
2. URL 映射不完整
3. `FFmpeg` 映射明显错误
4. 存在“猜 URL”逻辑，这对实验复现是不可接受的

### 结论

Docker 版本必须新增一套**专门的 repo 初始化机制**，不直接依赖当前脚本。

---

## 7. Docker 版 repo 初始化设计

### 7.1 总原则

clone 目标待测 repo 时，必须保证克隆的是**正确的上游仓库**。

如果 clone 错 repo，后续所有实验结果都失效。

所以 Docker 版 repo 初始化必须满足：

1. 不猜 URL
2. 不接受缺失映射
3. clone 后做校验
4. 支持无网离线恢复

### 7.2 建议新增的资产

下一步建议新增两类文件：

1. `repo/docker_repo_manifest.json`
2. `scripts/docker_init_repos.py`

其中：

- `docker_repo_manifest.json` 负责声明 9 个 repo 的**唯一允许来源**
- `docker_init_repos.py` 负责：
  - 在线 clone
  - 离线恢复
  - clone 后校验

### 7.3 manifest 应包含的字段

建议 manifest 至少包含：

```json
{
  "FFmpeg": {
    "canonical_url": "https://git.ffmpeg.org/ffmpeg.git",
    "fallback_urls": ["https://github.com/FFmpeg/FFmpeg.git"],
    "validation": {
      "required_tags": ["n4.2.2"],
      "required_paths": ["libavcodec/cbs_jpeg.c"]
    },
    "source_level": "official-main"
  }
}
```

其他 repo 同理。

### 7.4 clone 后必须做的校验

不能只看 clone 是否成功，必须至少做三类校验：

1. `git remote get-url origin`

   - 必须命中 manifest 允许的 URL 集合
2. `git tag -l`

   - 必须存在该项目在数据集中实际会用到的历史 tag
3. `git ls-tree` / `git cat-file -e`

   - 必须存在该 repo 的关键路径或标志性文件

必要时可额外做：

4. sentinel commit / sentinel tag 校验
   - 为每个 repo 固定 1-3 个已知标签或已知路径

### 7.5 绝不能使用的做法

1. `https://github.com/{repo_name}/{repo_name}.git` 猜测 URL
2. `--depth 1`
3. 不拉 tag
4. clone 成功就直接认为 repo 正确

---

## 8. 当前数据集中的 9 个 repo 及推荐来源

根据当前 `BaseDataSet.json` / `BaseDataTest.json`，实际涉及的 repo 为：

- `FFmpeg`
- `ImageMagick`
- `curl`
- `httpd`
- `linux`
- `openjpeg`
- `openssl`
- `qemu`
- `wireshark`

下表是当前建议的默认来源，已经按官方项目文档或官方项目主页核对：

| repo            | 推荐 clone URL                                                         | 来源级别                   | 说明                                                                           |
| --------------- | ---------------------------------------------------------------------- | -------------------------- | ------------------------------------------------------------------------------ |
| `FFmpeg`      | `https://git.ffmpeg.org/ffmpeg.git`                                  | official-main              | FFmpeg 官网明确给出主 Git 仓库；GitHub 为 mirror                               |
| `ImageMagick` | `https://github.com/ImageMagick/ImageMagick.git`                     | authoritative-source       | ImageMagick 官网明确称其 authoritative source repository 在 GitHub             |
| `curl`        | `https://github.com/curl/curl.git`                                   | official                   | curl 官方源码页明确给出该地址                                                  |
| `httpd`       | `https://github.com/apache/httpd.git`                                | ASF mirror                 | Apache 官方 Git 体系的公开镜像，适合匿名 clone；后续可加 GitBox 只读源作为备选 |
| `linux`       | `https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git` | official-mainline          | kernel.org / Torvalds 主线仓库                                                 |
| `openjpeg`    | `https://github.com/uclouvain/openjpeg.git`                          | official                   | 仓库首页明确标注 official repository                                           |
| `openssl`     | `https://github.com/openssl/openssl.git`                             | official-downstream-public | OpenSSL 官方文档明确说公共访问仓库在 GitHub                                    |
| `qemu`        | `https://gitlab.com/qemu-project/qemu.git`                           | official                   | QEMU 官方贡献文档明确给出该 clone 地址                                         |
| `wireshark`   | `https://gitlab.com/wireshark/wireshark.git`                         | official                   | Wireshark 开发文档明确说明官方仓库在 GitLab                                    |

### 对 `httpd` 的特别说明

`apache/httpd` 在 GitHub 上是 Apache 维护的公开镜像，不是社区私有 fork。如果后续需要更严格，可再给它加一条 canonical 备选：

- `https://gitbox.apache.org/repos/asf/httpd.git`

但匿名构建场景下，GitHub 镜像更稳妥。

### 参考来源

- FFmpeg 官方下载页与 Git howto：
  - https://www.ffmpeg.org/download.html
  - https://ffmpeg.org/git-howto.html
- ImageMagick 官方安装页：
  - https://imagemagick.org/install-source/
- curl 官方源码页：
  - https://curl.se/dev/source.html
- OpenSSL 官方 Git repo 文档：
  - https://www.openssl-library.org/source/gitrepo/
- QEMU 官方贡献页：
  - https://www.qemu.org/contribute/
- Wireshark 开发文档与官方 GitLab：
  - https://www.wireshark.org/docs/wsdg_html_chunked/ChSrcGitRepository.html
  - https://gitlab.com/wireshark/wireshark

---

## 9. 在线模式与离线模式必须分开设计

这是这次 Docker 设计里最关键的一点。

### 9.1 在线模式

如果目标环境允许联网：

- 由 `docker_init_repos.py` 按 manifest clone 指定 repo
- 默认 clone 全部 9 个
- 用户指定时只 clone 指定的 1 个或 N 个

例如：

```bash
python scripts/docker_init_repos.py --repos all
python scripts/docker_init_repos.py --repos curl
python scripts/docker_init_repos.py --repos curl,openssl,qemu
```

### 9.2 离线模式

如果目标环境不允许联网：

就**不能**要求目标环境再执行 `git clone`。

因此必须在镜像中预置 repo 数据。

### 9.3 推荐的离线封装方式

不是直接把 9 个 working tree 裸拷进去，而是建议预置：

- bare mirror
  或
- `.bundle` 文件

例如：

```text
/root/VulnVersion/repo-cache/FFmpeg.bundle
/root/VulnVersion/repo-cache/curl.bundle
...
```

然后容器启动时：

- 若 `repo/<name>/.git` 不存在
- 且 `repo-cache/<name>.bundle` 存在
- 则从本地 bundle 恢复 repo

这样有 3 个优势：

1. 满足离线恢复
2. 比直接预置 working tree 更干净
3. 仍可按用户要求只恢复部分 repo

### 9.4 最终建议

建议后续至少支持两种镜像形态：

1. `vulnversion-core`

   - 主项目 + OpenCode + NVD cache
   - 不带 repo cache
   - 适合在线环境
2. `vulnversion-offline-allrepos`

   - 主项目 + OpenCode + NVD cache + 9 个 repo bundle / mirror
   - 适合真正离线复现实验

如果只测试单个 repo，也可以在构建时做：

- `vulnversion-offline-curl`
- `vulnversion-offline-ffmpeg`

---

## 10. OpenCode / 本地模型 / 自定义 API provider 设计

### 10.1 当前现状

当前项目中有两层配置：

1. Python 侧：

   - [vulnversion/config.py](/e:/AI/Agent/workflow/VulnVersion/vulnversion/config.py)
   - 会从项目根 `.env` 自动加载：
     - `OPENCODE_PROVIDER_ID`
     - `OPENCODE_MODEL_ID`
     - `OPENAI_MODEL`
     - 等变量
2. OpenCode 侧：

   - `.opencode/opencode.json`
   - `start_opencode.sh` 会 source `.env`

### 10.2 Docker 版推荐原则

不要把“当前仓库里的真实 provider 和 apiKey”当成最终镜像配置。

Docker 版应该设计成：

1. 镜像内部只保存**模板或占位配置**
2. 用户通过 `.env` 或 `docker run --env-file` 提供真实值
3. OpenCode 在容器启动时读取这些变量

### 10.3 推荐的 provider 设计方式

优先采用：

`OpenAI-compatible provider`

因为这样无论你接的是：

- 本地 vLLM
- 本地 SGLang
- 本地 LM Studio
- 本地 FastAPI 包装模型
- 校内私有代理
- 任意兼容 `/v1` 的接口

都能统一成一组环境变量：

```bash
OPENAI_BASE_URL=http://127.0.0.1:8000/v1
OPENAI_API_KEY=dummy-or-real
OPENAI_MODEL=your-model-name
OPENCODE_PROVIDER_ID=local-openai
OPENCODE_MODEL_ID=your-model-name
```

### 10.4 OpenCode 配置模板建议

由于 OpenCode 配置层支持：

- `{env:VAR}` 替换

可将 `.opencode/opencode.json` 改造成模板式配置。

OpenCode 本身在配置解析时就支持 `{env:VAR}`：

- [config/paths.ts](/e:/AI/Agent/workflow/Replication/AgentEnhancement/Agent/opencode/opencode/packages/opencode/src/config/paths.ts:77)

因此 Docker 版推荐设计是：

```json
{
  "$schema": "https://opencode.ai/config.json",
  "provider": {
    "local-openai": {
      "name": "Local OpenAI-Compatible",
      "npm": "@ai-sdk/openai-compatible",
      "models": {
        "{env:OPENCODE_MODEL_ID}": {
          "name": "{env:OPENCODE_MODEL_ID}"
        }
      },
      "options": {
        "baseURL": "{env:OPENAI_BASE_URL}",
        "apiKey": "{env:OPENAI_API_KEY}"
      }
    }
  }
}
```

### 10.5 三种可支持模式

Docker 版推荐同时支持：

1. `.env` 模式

   - 最简单，适合实验复现
2. `docker run --env-file ...`

   - 适合服务器部署
3. 用户挂载自定义 `.opencode/opencode.json`

   - 适合高级用户完全自定义 provider

### 10.6 设计结论

后续 Dockerfile / entrypoint 应支持：

1. 默认读取 `.env`
2. 若用户传入环境变量，则覆盖 `.env`
3. OpenCode provider 与 Python 侧模型 ID 保持一致

---

## 11. `curl` 安装与 `nvd_crawler.py` 兼容

你要求在 Ubuntu 容器中安装 `curl`，这一点是必须的。

### 必须安装

Dockerfile 中必须包含：

- `curl`

### 但是仅安装 `curl` 还不够

因为当前：

- [DataSet/nvd_crawler.py](/e:/AI/Agent/workflow/VulnVersion/DataSet/nvd_crawler.py:17)

写死调用的是：

```python
"curl.exe"
```

这意味着：

- Ubuntu 容器里即使装了 `/usr/bin/curl`
- 代码仍然会因为找不到 `curl.exe` 而失败

### Docker 版临时兼容方案

在不改 Python 代码的前提下，Dockerfile 里建议额外做一层兼容：

```bash
ln -s /usr/bin/curl /usr/local/bin/curl.exe
```

这样可以先保证现有 `nvd_crawler.py` 在 Ubuntu 容器中可执行。

### 长期正确方案

后续仍建议把 `nvd_crawler.py` 改为：

- `curl`
  或
- `httpx / requests`

但这属于代码层修复，不是本次 `docker.md` 的唯一依赖。

---

## 12. `BaseData_nvd.json` 必须进入镜像

这一条保持不变，而且现在优先级更高。

必须进入镜像的 NVD 缓存文件：

- `DataSet/BaseData_nvd.json`

理由：

1. 便于离线复现
2. 可以减少 crawler 触发
3. 即使 crawler 临时不可用，也不影响大多数已有 CVE 的运行

---

## 13. 必须进入镜像的内容

### 主项目

- `main.py`
- `requirements.txt`
- `vuln_config.json`
- `start_opencode.sh`
- `start_opencode.cmd`
- `vulnversion/`
- `.opencode/`

### 数据与运行脚本

- `DataSet/BaseDataTest.json`
- `DataSet/BaseDataSet.json`
- `DataSet/BaseDataSet_30.json`
- `DataSet/BaseData_nvd.json`
- `DataSet/nvd_crawler.py`

### 目录

- `Result/`
- `repo/`

### 离线模式可选附加内容

- `repo-cache/`

---

## 14. 不应进入镜像的内容

继续维持以下排除规则：

1. `DataSet/CveDetail/`
2. `docs/`
3. `tests/`
4. `Result/*`
5. `Result_step12/`
6. `Result-5.2/`
7. `Result-old/`
8. `Replication/`
9. `SystemDesign/`
10. 根目录 `node_modules/`
11. `.opencode/node_modules/`

---

## 15. 对 `tests/` 的判断

当前 `VulnVersion` 正常运行链：

- `main.py`
- `vulnversion/`

不依赖 `tests/`。

因此：

- Docker 运行镜像不需要携带 `tests/`

这条判断保持不变。

---

## 16. Dockerfile 下一步必须实现的机制

下一步生成 Dockerfile 时，必须明确实现以下能力：

1. 安装：

   - Python 3.11
   - git
   - curl
   - Node.js
   - npm
   - OpenCode：`npm i -g opencode-ai`
2. 设定：

   - `WORKDIR /root/VulnVersion`
3. 放入：

   - `.opencode/`
   - `BaseData_nvd.json`
4. 处理：

   - `chmod +x start_opencode.sh`
   - `ln -s /usr/bin/curl /usr/local/bin/curl.exe`
5. 准备目录：

   - `mkdir -p Result repo`
6. 预留 repo 初始化接口：

   - 在线 clone
   - 离线 bundle 恢复
7. 支持 provider 注入：

   - `.env`
   - `--env-file`
   - 用户挂载自定义 `opencode.json`

---

## 17. 当前最重要的设计结论

这里是这次改进后最关键的 6 个结论：

1. 用于跨环境复现的交付物应是**预构建镜像 tar 包**，不是让目标机重新拿源码
2. `COPY` 仍然可以用于构建阶段，但目标机运行时不依赖宿主源码
3. Docker 版 repo 初始化必须脱离现有 `clone_all_repos.py`
4. repo 不能再猜 URL，必须走 `repo manifest + 校验`
5. OpenCode/provider 必须改成 env 驱动，而不是继续依赖仓库里的硬编码真实配置
6. Ubuntu 容器中除了安装 `curl`，还必须兼容当前 `curl.exe` 调用

---

## 18. 下一步建议

基于这份设计，下一步应实现：

1. `Dockerfile`
2. `.dockerignore`
3. `scripts/docker_init_repos.py`
4. `repo/docker_repo_manifest.json`
5. 可选：
   - `scripts/render_opencode_config.py`
   - `entrypoint.sh`

这几项做完之后，Docker 版 `VulnVersion` 才真正具备：

- 在线构建
- 离线迁移
- 正确 repo 初始化
- 本地模型 / 自定义 API 接入
- NVD cache 复现

这才是适合论文复现实验分发的版本。
