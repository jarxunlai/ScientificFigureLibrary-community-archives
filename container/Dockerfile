FROM rocker/r-ver:4.4.3@sha256:aa952afb35853aaf5c67bd224aa969caf6ad49395d69cf19a586f1554ed3bd05

LABEL org.opencontainers.image.title="SFL archive render validator" \
      org.opencontainers.image.version="r-4.4.3-v2-ggplot" \
      org.opencontainers.image.source="https://github.com/jarxunlai/ScientificFigureLibrary-community-archives"

USER root
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      ca-certificates \
      fonts-liberation \
      libfontconfig1-dev \
      libfreetype6-dev \
      libfribidi-dev \
      libharfbuzz-dev \
      libjpeg-dev \
      libpng-dev \
      libtiff-dev && \
    rm -rf /var/lib/apt/lists/*

COPY 99-sfl-arial.conf /etc/fonts/conf.d/99-sfl-arial.conf
RUN fc-cache -f

RUN Rscript --vanilla -e "options(Ncpus=2); install.packages(c('ggplot2','readr','ragg'), repos='https://cloud.r-project.org')" && \
    Rscript --vanilla -e "stopifnot(requireNamespace('ggplot2', quietly=TRUE), requireNamespace('readr', quietly=TRUE), requireNamespace('ragg', quietly=TRUE)); writeLines(c(as.character(packageVersion('ggplot2')), as.character(packageVersion('readr')), as.character(packageVersion('ragg'))))"

COPY run-render.R /opt/sfl/run-render.R

RUN groupadd --gid 65532 sfl && \
    useradd --uid 65532 --gid 65532 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin sfl && \
    chmod 0555 /opt/sfl/run-render.R /etc/fonts/conf.d/99-sfl-arial.conf

USER 65532:65532
WORKDIR /nonexistent
ENTRYPOINT ["Rscript", "--vanilla", "/opt/sfl/run-render.R"]
