FROM ubuntu:24.04

ARG VV_GIT_URL=https://github.com/Jimi-Lab/VulnVersion.git
ARG VV_GIT_REF=main
ARG MINIFORGE_VERSION=24.11.3-0
ARG MINIFORGE_FILE=Miniforge3-${MINIFORGE_VERSION}-Linux-x86_64.sh
ARG MINIFORGE_URL=https://github.com/conda-forge/miniforge/releases/download/${MINIFORGE_VERSION}/${MINIFORGE_FILE}

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=Etc/UTC \
    CONDA_DIR=/opt/conda \
    PATH=/opt/conda/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_ROOT_USER_ACTION=ignore \
    CONDA_ENV_NAME=VulnVersion \
    OPENCODE_HOST=127.0.0.1 \
    OPENCODE_PORT=4096 \
    VV_REPOS= \
    VV_DATASET=DataSet/BaseDataOrder.json

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    bzip2 \
    ca-certificates \
    curl \
    git \
    tini \
    wget \
  && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL "${MINIFORGE_URL}" -o /tmp/miniforge.sh \
 && bash /tmp/miniforge.sh -b -p "${CONDA_DIR}" \
 && rm -f /tmp/miniforge.sh \
 && conda config --system --set always_yes yes --set changeps1 no \
 && conda clean -afy

WORKDIR /root

RUN git clone "${VV_GIT_URL}" VulnVersion \
 && git -C VulnVersion checkout "${VV_GIT_REF}" \
 && ACTUAL_SHA="$(git -C VulnVersion rev-parse HEAD)" \
 && printf "VV_GIT_URL=%s\nVV_GIT_REF=%s\nVV_GIT_COMMIT=%s\n" \
      "${VV_GIT_URL}" "${VV_GIT_REF}" "${ACTUAL_SHA}" > /root/VulnVersion/.build_ref

WORKDIR /root/VulnVersion

# Overwrite project config templates with safe, env-driven Docker variants.
COPY docker/Internet/opencode.internet.json ./opencode.json
COPY docker/Internet/.env.example ./.env.example
COPY docker/Internet/docker-entrypoint.sh /usr/local/bin/vv-entrypoint
COPY docker/Internet/run_vulnversion.sh /usr/local/bin/vv-run

RUN rm -rf \
      docs \
      tests \
      DataSet/CveDetail \
      Result/* \
      Result-5.2 \
      Result-BeforeEdit \
      Result-old \
      Result_step12 \
      node_modules \
      .opencode/node_modules \
 && mkdir -p Result repo \
 && chmod +x start_opencode.sh /usr/local/bin/vv-entrypoint /usr/local/bin/vv-run \
 && conda env create -f environment.yml \
 && conda run -n VulnVersion python --version \
 && conda run -n VulnVersion git --version \
 && conda run -n VulnVersion curl --version \
 && conda run -n VulnVersion node -v \
 && conda run -n VulnVersion npm -v \
 && conda run -n VulnVersion npm i -g opencode-ai@1.2.26 \
 && conda run -n VulnVersion opencode --help >/dev/null \
 && if [[ -f .opencode/package.json ]]; then \
      pushd .opencode >/dev/null; \
      conda run -n VulnVersion npm install --omit=dev; \
      popd >/dev/null; \
    fi \
 && conda clean -afy \
 && rm -rf /root/.npm /tmp/*

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/vv-entrypoint"]
CMD ["bash"]
