# Bootstrap only. This context is not accepted by the Archive PR validator.
ARG PIXI_IMAGE=ghcr.io/prefix-dev/pixi@sha256:ad4daaf2f85798f3f88d0489a3b4a7e92c33358709560fb5adf83242803cccbe
ARG RUNTIME_IMAGE=docker.io/library/debian@sha256:5ae3c39ebd15e229dcedd5cee596b2497182493d41ff162e824ba13fc1b2b867

FROM ${PIXI_IMAGE} AS environment
WORKDIR /opt/sfl
COPY pixi.toml pixi.lock ./
RUN pixi install --frozen --platform linux-64

FROM ${RUNTIME_IMAGE}

LABEL org.opencontainers.image.title="SFL archive renderer bootstrap (R entry)" \
      org.opencontainers.image.source="https://github.com/jarxunlai/ScientificFigureLibrary-community-archives" \
      org.opencontainers.image.version="0.7-bootstrap"

COPY --from=environment /opt/sfl/.pixi/envs/default /opt/sfl/.pixi/envs/default
COPY r/runner.py /opt/sfl/runner.py

ENV PATH="/opt/sfl/.pixi/envs/default/bin" \
    LD_LIBRARY_PATH="/opt/sfl/.pixi/envs/default/lib" \
    R_HOME="/opt/sfl/.pixi/envs/default/lib/R" \
    MPLCONFIGDIR="/tmp/sfl-matplotlib"

RUN set -eux; \
    groupadd --gid 65532 sfl; \
    useradd --uid 65532 --gid 65532 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin sfl; \
    chmod 0555 /opt/sfl/runner.py; \
    /opt/sfl/.pixi/envs/default/bin/python /opt/sfl/runner.py --verify-runtime; \
    rm -rf /etc/apt /var/lib/apt /var/cache/apt /usr/lib/apt /usr/lib/dpkg /var/lib/dpkg; \
    rm -f /usr/bin/apt /usr/bin/apt-get /usr/bin/apt-cache /usr/bin/apt-config /usr/bin/dpkg /usr/bin/dpkg-*; \
    rm -f /usr/bin/curl /usr/bin/wget /usr/bin/git /usr/bin/git-*; \
    find /opt/sfl/.pixi/envs/default/bin -maxdepth 1 \
      \( -name 'curl' -o -name 'curl-config' -o -name 'wget' -o -name 'git' -o -name 'git-*' -o -name 'pip' -o -name 'pip3*' \) \
      -delete; \
    rm -f /bin/sh /bin/bash /bin/dash /usr/bin/sh /usr/bin/bash /usr/bin/dash; \
    /opt/sfl/.pixi/envs/default/bin/python /opt/sfl/runner.py --verify-runtime

USER 65532:65532
WORKDIR /nonexistent
ENTRYPOINT ["/opt/sfl/.pixi/envs/default/bin/python", "/opt/sfl/runner.py"]
