FROM rocker/r-ver:4.4.3@sha256:aa952afb35853aaf5c67bd224aa969caf6ad49395d69cf19a586f1554ed3bd05

LABEL org.opencontainers.image.title="SFL archive render validator" \
      org.opencontainers.image.version="r-4.4.3-v1" \
      org.opencontainers.image.source="https://github.com/jarxunlai/ScientificFigureLibrary-community-archives"

COPY run-render.R /opt/sfl/run-render.R

RUN groupadd --gid 65532 sfl && \
    useradd --uid 65532 --gid 65532 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin sfl && \
    chmod 0555 /opt/sfl/run-render.R

USER 65532:65532
WORKDIR /nonexistent
ENTRYPOINT ["Rscript", "--vanilla", "/opt/sfl/run-render.R"]
