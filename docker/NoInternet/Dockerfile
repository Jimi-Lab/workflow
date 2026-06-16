FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=Etc/UTC \
    PIP_NO_CACHE_DIR=1 \
    PIP_ROOT_USER_ACTION=ignore \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    VV_REPOS=all

WORKDIR /root/VulnVersion

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    ca-certificates \
    curl \
    git \
    nodejs \
    npm \
    python3 \
    python3-pip \
    python3-venv \
    ripgrep \
    tini \
  && rm -rf /var/lib/apt/lists/*

RUN ln -sf /usr/bin/python3 /usr/local/bin/python \
 && ln -sf /usr/bin/pip3 /usr/local/bin/pip \
 && ln -sf /usr/bin/curl /usr/local/bin/curl.exe

# Core project files
COPY VulnVersion/main.py ./
COPY VulnVersion/requirements.txt ./
COPY VulnVersion/vuln_config.json ./
COPY VulnVersion/start_opencode.sh ./
COPY VulnVersion/start_opencode.cmd ./
COPY VulnVersion/vulnversion ./vulnversion

# OpenCode project assets without carrying host node_modules or host secrets.
COPY VulnVersion/.opencode/package.json ./.opencode/package.json
COPY VulnVersion/.opencode/bun.lock ./.opencode/bun.lock
COPY VulnVersion/.opencode/.gitignore ./.opencode/.gitignore
COPY VulnVersion/.opencode/skills ./.opencode/skills
COPY VulnVersion/.opencode/tools ./.opencode/tools
COPY docker/NoInternet/opencode.offline.json ./opencode.json

# Dataset assets needed for offline execution.
COPY VulnVersion/DataSet/BaseDataSet.json ./DataSet/BaseDataSet.json
COPY VulnVersion/DataSet/BaseDataSet_30.json ./DataSet/BaseDataSet_30.json
COPY VulnVersion/DataSet/BaseDataTest.json ./DataSet/BaseDataTest.json
COPY VulnVersion/DataSet/BaseData_nvd.json ./DataSet/BaseData_nvd.json
COPY VulnVersion/DataSet/nvd_crawler.py ./DataSet/nvd_crawler.py

# Offline repo bundles and runtime helpers.
COPY docker/NoInternet/repo-bundles ./repo-bundles
COPY docker/NoInternet/docker-entrypoint.sh /usr/local/bin/vv-entrypoint
COPY docker/NoInternet/run_vulnversion.sh /usr/local/bin/vv-run
COPY docker/NoInternet/.env.example ./.env.example
COPY docker/NoInternet/README.md /opt/vulnversion-offline/README.md

RUN chmod +x ./start_opencode.sh /usr/local/bin/vv-entrypoint /usr/local/bin/vv-run \
 && mkdir -p Result repo /opt/vulnversion-offline \
 && pip install -r requirements.txt \
 && npm i -g opencode-ai \
 && cd .opencode && npm install --omit=dev \
 && rm -rf /root/.npm /tmp/*

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/vv-entrypoint"]
CMD ["bash"]
