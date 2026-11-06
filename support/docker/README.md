# Pinned build SDK

This container builds research artifacts; it is not the NAS root filesystem.
The Debian base digest, snapshot20260925T000000Z, three suites and29requested
packages remain fixed. No rolling repository selects their versions.
The materialized SDK indexes are amd64; use `--platform linux/amd64` on ARM hosts.

BuildKit fetches the exact original signed InRelease and Packages.xz objects
for bookworm, bookworm-updates and bookworm-security into a local repository.
Every ADD requires SHA-256; APT still authenticates the original metadata using
Debian's archive keyring. Original metadata came from
`https://snapshot.debian.org/archive/{debian,debian-security}/20260925T000000Z/`.
To update it, verify each original Release signature, its index hash/size, then
update all corresponding ADD checksums/locators together. SHA-1 in Snapshot file
URLs identifies an object; it never authenticates it.

APT prints its exact package plan with SHA256 forced. The internal installer
fetches those objects from the official Debian pool, requiring each expected
SHA-256, then installs with `--no-download`. Two historical objects use fixed
Snapshot locators selected by their expected SHA-256. Missing, malformed or
incorrect objects refuse; no newer version or automatic retry is substituted.

The slim base lacks HTTPS trust. A dated public Mozilla extract is fetched into
existing `/usr/share` with mandatory SHA-256, selected explicitly by CAInfo, and
removed after Debian installs its ordinary CA package. No certificate/key payload
is in Git. Its [source/checksums/license](https://curl.se/docs/caextract.html)
remain upstream; update dated URL/hash together and never disable verification.

| Phase | Absolute bound | Failure |
| --- | --- | --- |
| APT metadata |120 s +5 s kill grace|`phase=update`, original status|
| Plan, download and install together |480 s +5 s kill grace|`phase=install`, original status|
| QEMU SDK workflow step including ADD |12 min|Independent workflow bound|

Transport idle bounds are20s with zero retries. Failed update cannot install;
failed installation cannot run final cleanup. These are SDK limits, not hardware
performance budgets. Run `python3 -B support/tests/test-sdk-apt-budgets.py` on
Linux for actual-shell failure controls. A full Docker SDK build and exact-head
hosted firmware checks remain separate qualifications; stub tests waive neither.
