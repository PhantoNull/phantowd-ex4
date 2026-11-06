FROM debian:12-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171

# Bootstrap HTTPS before ca-certificates can be installed. BuildKit verifies
# this dated public Mozilla bundle in an existing directory. Remove it after
# Debian's ca-certificates package has installed its ordinary trust store.
ADD --chmod=0644 --checksum=sha256:427c064216761a1e72a8b30f0d954d08cb6e4435a82091fb865afd20c8497285 \
    https://curl.se/ca/cacert-2026-11-05.pem \
    /usr/share/phantowd-sdk-bootstrap-ca.crt

# Exact signed metadata from snapshot20260925T000000Z; never rolling indexes.
RUN mkdir -p /var/cache/apt/archives/partial \
    /tmp/sdk-snapshot/debian/dists/bookworm/main/binary-amd64 \
    /tmp/sdk-snapshot/debian/dists/bookworm-updates/main/binary-amd64 \
    /tmp/sdk-snapshot/debian-security/dists/bookworm-security/main/binary-amd64

ADD --chmod=0644 --checksum=sha256:77737fa4b34f2693e982cc9ee35736816c35a7778fc2d326cc1bbf5b301fe1aa \
    https://snapshot.debian.org/file/736a99b8b096598d48c438eb356bd074fecfbf23/InRelease \
    /tmp/sdk-snapshot/debian/dists/bookworm/InRelease

ADD --chmod=0644 --checksum=sha256:9e0b5aabb2465b3d2e7a7fe27f9913846277833f7a2826e7767acccff5b588c5 \
    https://deb.debian.org/debian/dists/bookworm/main/binary-amd64/by-hash/SHA256/9e0b5aabb2465b3d2e7a7fe27f9913846277833f7a2826e7767acccff5b588c5 \
    /tmp/sdk-snapshot/debian/dists/bookworm/main/binary-amd64/Packages.xz

ADD --chmod=0644 --checksum=sha256:ecd2a6713a8d2e02c07d914d71f2a73519a7049746cf6a9de6898fae894e927d \
    https://snapshot.debian.org/file/ae012b26e2d6b20288a180040450b5d2b52a402d/InRelease \
    /tmp/sdk-snapshot/debian/dists/bookworm-updates/InRelease

ADD --chmod=0644 --checksum=sha256:87e7e94047fb7fb6f4ceecc7022d4bee55b66031cc2a7666d3196f3e0aabb846 \
    https://snapshot.debian.org/file/c6196a06b4270d1020fdf3d05f3c2ceba459d75d/Packages.xz \
    /tmp/sdk-snapshot/debian/dists/bookworm-updates/main/binary-amd64/Packages.xz

ADD --chmod=0644 --checksum=sha256:9b985254dbf48bd5413ee93b6a27e3b8bde0695f0493bea6eaf4698536533dce \
    https://snapshot.debian.org/file/c76edb6516b9f0b2252f3f42360b489851578a35/InRelease \
    /tmp/sdk-snapshot/debian-security/dists/bookworm-security/InRelease

ADD --chmod=0644 --checksum=sha256:488f624377e2010dbded69adadfa7626b96521df29be2e9aa8c9a75a0801b2ea \
    https://snapshot.debian.org/file/d55f726662acc481d604d0ce98f7e7aca88f664f/Packages.xz \
    /tmp/sdk-snapshot/debian-security/dists/bookworm-security/main/binary-amd64/Packages.xz

COPY support/docker/debian-snapshot.sources /etc/apt/sources.list.d/debian.sources

COPY --chmod=0755 support/docker/sdk-install.sh /usr/local/bin/phantowd-sdk-install

RUN set -eu; \
    timeout --signal=TERM --kill-after=5s 120s apt-get \
        -o APT::Update::Error-Mode=any -o Acquire::Retries=0 \
        -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20 \
        -o Acquire::https::CAInfo=/usr/share/phantowd-sdk-bootstrap-ca.crt update \
    || { sdk_status=$?; printf 'PHANTOWD_SDK_APT_FAILURE phase=update status=%s budget_seconds=120\n' "$sdk_status" >&2; exit "$sdk_status"; }; \
    DEBIAN_FRONTEND=noninteractive timeout --signal=TERM --kill-after=5s 480s \
        phantowd-sdk-install -o Acquire::Retries=0 \
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
