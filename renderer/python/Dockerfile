# Bootstrap only. This context is not accepted by the Archive PR validator.
ARG PIXI_IMAGE=ghcr.io/prefix-dev/pixi@sha256:ad4daaf2f85798f3f88d0489a3b4a7e92c33358709560fb5adf83242803cccbe
ARG RUNTIME_IMAGE=docker.io/library/debian@sha256:5ae3c39ebd15e229dcedd5cee596b2497182493d41ff162e824ba13fc1b2b867

FROM ${PIXI_IMAGE} AS environment
WORKDIR /opt/sfl
COPY pixi.toml pixi.lock ./
RUN pixi install --frozen --platform linux-64

FROM ${RUNTIME_IMAGE}

LABEL org.opencontainers.image.title="SFL archive renderer bootstrap (Python entry)" \
      org.opencontainers.image.source="https://github.com/jarxunlai/ScientificFigureLibrary-community-archives" \
      org.opencontainers.image.version="0.7-bootstrap"

COPY --from=environment /opt/sfl/.pixi/envs/default /opt/sfl/.pixi/envs/default
COPY python/runner.py /opt/sfl/runner.py
COPY runtime_boundary.py sanitize_runtime.py /opt/sfl/bootstrap-tools/

ENV PATH="/opt/sfl/.pixi/envs/default/bin" \
    LD_LIBRARY_PATH="/opt/sfl/.pixi/envs/default/lib" \
    R_HOME="/opt/sfl/.pixi/envs/default/lib/R" \
    MPLCONFIGDIR="/tmp/sfl-matplotlib"

RUN set -eux; \
    groupadd --gid 65532 sfl; \
    useradd --uid 65532 --gid 65532 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin sfl; \
    chmod 0555 /opt/sfl/runner.py; \
    /opt/sfl/.pixi/envs/default/bin/python /opt/sfl/bootstrap-tools/sanitize_runtime.py --root /; \
    rm -rf /opt/sfl/bootstrap-tools

USER 65532:65532
WORKDIR /nonexistent
RUN ["/opt/sfl/.pixi/envs/default/bin/python", "/opt/sfl/runner.py", "--verify-runtime"]
ENTRYPOINT ["/opt/sfl/.pixi/envs/default/bin/python", "/opt/sfl/runner.py"]
