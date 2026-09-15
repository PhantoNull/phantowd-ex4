FROM debian:12-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        bash \
        bc \
        binutils \
        build-essential \
        bzip2 \
        ca-certificates \
        cpio \
        curl \
        file \
        findutils \
        git \
        gnupg \
        gosu \
        gzip \
        libncurses-dev \
        patch \
        perl \
        python3 \
        python3-flake8 \
        python3-magic \
        qemu-system-arm \
        rsync \
        sed \
        shellcheck \
        tar \
        unzip \
        wget \
        xz-utils \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 1000 builder \
    && useradd --uid 1000 --gid 1000 --create-home --shell /bin/sh builder

COPY support/docker/entrypoint.sh /usr/local/bin/phantowd-build-entrypoint
RUN chmod 0755 /usr/local/bin/phantowd-build-entrypoint

ENV LANG=C.UTF-8
WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/phantowd-build-entrypoint"]
