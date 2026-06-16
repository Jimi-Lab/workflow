# VulnVersion Offline Docker

这套文件用于构建“跨机器离线复现实验镜像”。

## 1. Bundle 结论

对当前 `VulnVersion` 而言，bundle 可以满足运行所需的 Git 历史需求，且**不需要修改 VulnVersion 代码**，前提是：

1. 每个 bundle 来自**完整仓库**，而不是 shallow / partial clone
2. bundle 使用：

```bash
git bundle create <repo>.bundle --all
```

3. 容器内恢复成**普通工作树仓库**，也就是 `repo/<name>/.git` 结构，而不是 bare repo

原因：

- VulnVersion 依赖的是：
  - `git log`
  - `git tag`
  - `git show`
  - `git grep`
  - `git blame`
  - `git merge-base`
  - `git rev-list --ancestry-path`
  - `git log -S/-G/-L`
- 这些能力只要 bundle 恢复成完整普通仓库就可以工作
- 代码不依赖网络 `fetch/pull/clone`
- 唯一和普通本地历史不同的是 `branch -r --contains` 只作为 `branch_hints`
  - 用 `git clone <bundle> <repo>` 恢复时，remote-tracking branches 仍然存在，足以满足当前代码

## 2. Bundle 放置位置

把 bundle 文件放到：

```text
docker/NoInternet/repo-bundles/
```

文件名必须和数据集中的 repo 名严格一致：

- `FFmpeg.bundle`
- `ImageMagick.bundle`
- `curl.bundle`
- `httpd.bundle`
- `linux.bundle`
- `openjpeg.bundle`
- `openssl.bundle`
- `qemu.bundle`
- `wireshark.bundle`

## 3. 生成 bundle

在构建镜像之前，于联网且已验证 repo 正确的构建机上执行：

```bash
git -C VulnVersion/repo/FFmpeg bundle create docker/NoInternet/repo-bundles/FFmpeg.bundle --all
git -C VulnVersion/repo/ImageMagick bundle create docker/NoInternet/repo-bundles/ImageMagick.bundle --all
git -C VulnVersion/repo/curl bundle create docker/NoInternet/repo-bundles/curl.bundle --all
git -C VulnVersion/repo/httpd bundle create docker/NoInternet/repo-bundles/httpd.bundle --all
git -C VulnVersion/repo/linux bundle create docker/NoInternet/repo-bundles/linux.bundle --all
git -C VulnVersion/repo/openjpeg bundle create docker/NoInternet/repo-bundles/openjpeg.bundle --all
git -C VulnVersion/repo/openssl bundle create docker/NoInternet/repo-bundles/openssl.bundle --all
git -C VulnVersion/repo/qemu bundle create docker/NoInternet/repo-bundles/qemu.bundle --all
git -C VulnVersion/repo/wireshark bundle create docker/NoInternet/repo-bundles/wireshark.bundle --all
```

## 4. 构建镜像

从工作区根目录 `E:\AI\Agent\workflow` 构建：

```bash
docker build -f docker/NoInternet/Dockerfile -t vulnversion-offline:latest .
```

## 5. 运行方式

### 交互式进入容器

```bash
docker run --rm -it \
  --env-file docker/NoInternet/.env.example \
  -e VV_REPOS=FFmpeg \
  vulnversion-offline:latest
```

### 一键运行 VulnVersion

```bash
docker run --rm -it \
  --env-file my-runtime.env \
  -e VV_REPOS=FFmpeg \
  -e VV_DATASET=DataSet/BaseDataTest.json \
  vulnversion-offline:latest \
  vv-run
```

### 跑多个 repo

```bash
docker run --rm -it \
  --env-file my-runtime.env \
  -e VV_REPOS=FFmpeg,openssl,curl \
  vulnversion-offline:latest \
  vv-run
```

## 6. 模型接入

该离线镜像不 bake 真实密钥。

离线镜像中的 OpenCode provider 配置应使用**项目根** `opencode.json`，而不是 `.opencode/opencode.json`。

推荐通过环境变量注入：

```bash
OPENAI_BASE_URL=http://127.0.0.1:8000/v1
OPENAI_API_KEY=dummy
OPENAI_MODEL=your-model-name
OPENCODE_PROVIDER_ID=local-openai
OPENCODE_MODEL_ID=your-model-name
```

其中：

- 项目根 `opencode.json` 负责定义 `local-openai` provider
- `.env` / `docker run --env-file` 负责提供：
  - `OPENAI_BASE_URL`
  - `OPENAI_API_KEY`
  - `OPENCODE_PROVIDER_ID`
  - `OPENCODE_MODEL_ID`

这意味着离线镜像运行时通常不需要手改：

- `~/.config/opencode/opencode.json`

也不再依赖：

- `.opencode/opencode.json`

镜像内项目根 `opencode.json` 已改成 env 驱动模板。

如果你要切到另一套自定义 LLM API，有两种方式：

1. 保持 `local-openai`，只修改：
   - `OPENAI_BASE_URL`
   - `OPENAI_API_KEY`
   - `OPENCODE_MODEL_ID`
2. 挂载你自己的项目根 `opencode.json`，并同步修改 `.env`

## 7. 设计注意事项

1. Dockerfile 已将 `DataSet/BaseData_nvd.json` 打进镜像
2. Dockerfile 已安装 `curl`
3. 为兼容当前 `nvd_crawler.py`，Dockerfile 还会创建：

```bash
/usr/local/bin/curl.exe -> /usr/bin/curl
```

4. 默认用 `VV_REPOS=all` 恢复全部 bundle
5. 若指定 repo 但缺少对应 bundle，容器会直接报错退出
6. 离线镜像中的 OpenCode 配置位置是项目根 `opencode.json`
