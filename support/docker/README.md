# Pinned build SDK

This container builds research artifacts. It is not the NAS root filesystem.
The Debian base digest, snapshot date and requested package roster are fixed.
APT still authenticates archive metadata with Debian's archive keyring.

Snapshot downloads use HTTPS. The slim base has no CA bundle, so BuildKit first
fetches a dated public Mozilla CA extract from curl into existing `/usr/share`,
requiring its SHA-256 and readable `0644` permissions. This avoids changing the
permissions of missing trust directories during remote ADD. No certificate
payload or key is checked into Git.
Both APT phases explicitly select that bundle with `Acquire::https::CAInfo`;
system trust discovery is unavailable before the package is installed.
After the snapshot's `ca-certificates` package installs the normal trust store,
the temporary bootstrap file is removed.
The extract's [source, checksums and MPL-2.0 license](https://curl.se/docs/caextract.html)
remain available upstream. Update its dated URL and checksum together only after
verifying the published checksum; never disable TLS or archive authentication.

| SDK phase | Absolute bound | Failure |
| --- | --- | --- |
| APT metadata |120 s +5 s hard-kill grace|`phase=update`, original exit status|
| APT installation |480 s +5 s hard-kill grace|`phase=install`, original exit status|
| QEMU workflow SDK step |12 min|Independent workflow bound|

APT transport idle bounds are20s with no automatic transport retries. Metadata
errors fail the build instead of accepting incomplete index warnings. Failed
update never installs packages; failed installation never runs index cleanup.
These are build-environment limits, not firmware/service/EX4 performance budgets.

Run `python3 -B support/tests/test-sdk-apt-budgets.py` on Linux for isolated
failure-propagation checks. A complete `docker build --file
support/docker/Dockerfile --tag phantowd/buildroot:ci .` is a separate networked
qualification; fake-tool tests do not prove archive availability or image parity.
