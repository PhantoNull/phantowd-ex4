FROM debian:12-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171

# Bootstrap HTTPS before ca-certificates can be installed. BuildKit verifies
# this dated public Mozilla bundle in an existing directory. Remove it after
# Debian's ca-certificates package has installed its ordinary trust store.
ADD --chmod=0644 --checksum=sha256:427c064216761a1e72a8b30f0d954d08cb6e4435a82091fb865afd20c8497285 \
    https://curl.se/ca/cacert-2026-11-05.pem \
    /usr/share/phantowd-sdk-bootstrap-ca.crt

COPY support/docker/debian-snapshot.sources /etc/apt/sources.list.d/debian.sources

RUN set -eu; \
    timeout --signal=TERM --kill-after=5s 120s apt-get \
        -o APT::Update::Error-Mode=any -o Acquire::Retries=0 \
        -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20 \
        -o Acquire::https::CAInfo=/usr/share/phantowd-sdk-bootstrap-ca.crt update \
    || { sdk_status=$?; printf 'PHANTOWD_SDK_APT_FAILURE phase=update status=%s budget_seconds=120\n' "$sdk_status" >&2; exit "$sdk_status"; }; \
    DEBIAN_FRONTEND=noninteractive timeout --signal=TERM --kill-after=5s 480s \
        apt-get -o Acquire::Retries=0 \
        -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20 \
        -o Acquire::https::CAInfo=/usr/share/phantowd-sdk-bootstrap-ca.crt \
        install -y --no-install-recommends \
        bash \
        bc \
        binutils \
        build-essential \
        bzip2 \
        ca-certificates \
        cmake \
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
    || { sdk_status=$?; printf 'PHANTOWD_SDK_APT_FAILURE phase=install status=%s budget_seconds=480\n' "$sdk_status" >&2; exit "$sdk_status"; }; \
    rm -f /usr/share/phantowd-sdk-bootstrap-ca.crt; \
    rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 1000 builder \
    && useradd --uid 1000 --gid 1000 --create-home --shell /bin/sh builder

COPY support/docker/entrypoint.sh /usr/local/bin/phantowd-build-entrypoint
RUN chmod 0755 /usr/local/bin/phantowd-build-entrypoint

ENV LANG=C.UTF-8
WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/phantowd-build-entrypoint"]
