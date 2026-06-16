## VulnVersion Ubuntu/Docker 可移植性整理

### 本次已完成的代码清理

1. 主入口为 `VulnVersion/main.py`
2. 运行时仓库路径继续保持为相对项目根的 `repo/<repo_name>/.git`，未使用硬编码宿主机绝对路径。
3. 新增 Linux/macOS 启动脚本 `VulnVersion/start_opencode.sh`。
4. `main.py` 中的 Windows 绝对路径示例注释已移除，改为相对路径示例。
5. `main.py`、`vulnversion/cli.py`、`tests/test_step2_with_affected_versions_only.py`、`tests/run_ffmpeg_dataset.py` 的 OpenCode 启动提示已改为平台无关表述。
6. 新增 `VulnVersion/requirements.txt`，用于 Docker / venv 的 pip 依赖安装。

### 仍保留但不影响运行的历史路径

1. `tests/step3_repo_reports/*` 和 `tests/step3_planning_report_30/*` 下的绝对路径属于历史生成报告，不参与运行时逻辑。
2. 这些文件目前保留原样，避免把实验产物和源码改动混在一起。

### Ubuntu/Docker 运行基线

建议运行基线：

- OS: Ubuntu
- Python: 3.11
- Node.js: 20+
- npm: 10+
- git CLI: 必须安装

说明：

- 当前 `environment.yml` 已将 Python 版本锁定为 `3.11`
- Docker / venv 路线建议使用 `requirements.txt`
- OpenCode 通过 npm 安装，不属于 Python 依赖

### Python 依赖管理

当前项目维护两套依赖入口：

1. `VulnVersion/environment.yml`
   适合 Conda 本地开发
2. `VulnVersion/requirements.txt`
   适合 Docker / venv / CI

`requirements.txt` 当前对应如下 pip 依赖：

- `pydantic>=2,<3`
- `jsonschema>=4,<5`
- `httpx>=0.27,<1`
- `tqdm>=4,<5`
- `pyyaml>=6,<7`
- `networkx>=3,<4`
- `tiktoken>=0.7,<1`
- `grep-ast>=0.3,<1`
- `beautifulsoup4>=4,<5`

推荐安装方式：

```bash
python3.11 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### OpenCode 安装与配置整理

#### 1. 安装 OpenCode

```bash
npm i -g opencode-ai
```

说明：

- npm 包名使用 `opencode-ai`
- 安装后的可执行文件仍然是 `opencode`

安装完成后应保证以下命令可用：

```bash
opencode --help
```

#### 2. OpenCode 启动

Linux / macOS：

```bash
chmod +x ./start_opencode.sh
./start_opencode.sh
```

Windows：

```powershell
.\start_opencode.cmd
```

或直接：

```bash
opencode serve --hostname 127.0.0.1 --port 4096 --print-logs
```

#### 3. OpenCode 配置文件

项目当前使用到两类配置：

1. `VulnVersion/vuln_config.json`
   负责 VulnVersion 连接参数，例如：

   - `opencode_base_url`
   - `opencode_provider_id`
   - `opencode_model_id`
2. `VulnVersion/.opencode/opencode.json`
   负责 OpenCode provider / model 配置

Docker 中建议：

- 不要把真实 API key 直接 bake 进镜像
- 优先通过挂载配置文件或环境变量注入
- `.env` 仅用于受信任环境

### 运行目录约束

VulnVersion 默认按项目根相对路径工作：

- 数据集：`DataSet/...`
- 仓库目录：`repo/<repo_name>`
- 产物目录：`Result/...`

因此容器内应保证如下结构存在：

```text
VulnVersion/
  main.py
  vuln_config.json
  requirements.txt
  DataSet/
  repo/
    <repo_name>/.git
```

### 容器内最小运行步骤

先启动 OpenCode：

```bash
./start_opencode.sh
```

再运行 VulnVersion：

```bash
python main.py --dataset DataSet/BaseDataTest.json --no-watch
```

如果要评估带 GT 的完整指标：

```bash
python main.py --dataset DataSet/BaseDataSet.json --no-watch
```

### Docker 化时的直接建议

1. 工作目录固定为项目根，例如 `/workspace/VulnVersion`
2. 使用相对路径调用：
   - `python main.py --dataset DataSet/BaseDataTest.json`
3. 将目标仓库预先放入：
   - `repo/<repo_name>/.git`
4. 为 `start_opencode.sh` 设置执行位：
   - `chmod +x start_opencode.sh`
5. 将 OpenCode 配置与密钥通过 volume / env 注入，而不是写死进镜像
6. 若镜像中需要同时运行 OpenCode 与 VulnVersion，确保：
   - OpenCode 监听 `127.0.0.1:4096`
   - `vuln_config.json` 中的 `opencode_base_url` 与之保持一致

### 本次验证

本次修改后已完成的本地验证：

```bash
python -m py_compile main.py vulnversion/cli.py tests/test_step2_with_affected_versions_only.py tests/run_ffmpeg_dataset.py vulnversion/opencode/hints.py
python main.py --help
python tests/test_all.py --help
```

验证目标：

- 新主入口可解析
- 旧兼容入口不失效
- 跨平台提示语编译通过
- Docker / Ubuntu 所需依赖入口已经明确
