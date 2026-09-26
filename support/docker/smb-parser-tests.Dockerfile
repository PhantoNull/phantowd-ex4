# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

# Optional host integration helper, never a target firmware component.
# The ARMv5 guest separately tests its Buildroot-selected Samba version.
FROM debian:12-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171

COPY support/docker/debian-snapshot.sources /etc/apt/sources.list.d/debian.sources
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends samba-common-bin \
    && rm -rf /var/lib/apt/lists/*

USER 65534:65534
ENTRYPOINT ["/tests/phantowd-api-linux.test"]
CMD ["-test.run=^TestQEMUSMBPreview$", "-test.v", "-test.timeout=60s"]
