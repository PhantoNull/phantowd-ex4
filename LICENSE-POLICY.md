# Licensing policy

PhantoWD EX4 uses per-file licensing recorded with SPDX metadata and the
[REUSE specification](https://reuse.software/spec/). The repository's original
source code, build tooling, and documentation are licensed under the Apache
License 2.0 unless a file says otherwise. The complete text is available in
`LICENSE` and `LICENSES/Apache-2.0.txt`.

Linux kernel changes, device trees derived from Linux or other GPL-2.0-only
inputs, and the corresponding patch files remain licensed under
GPL-2.0-only. Their complete license text is in
`LICENSES/GPL-2.0-only.txt`. SPDX headers in those files take precedence over
the repository default.

The Buildroot archive-helper cleanup patch retains upstream's
GPL-2.0-or-later licensing; its license text is in
`LICENSES/GPL-2.0-or-later.txt`. It is not an Apache-2.0 upstream derivative.

Third-party material retains its upstream copyright and license. Contributions
must not remove or weaken upstream notices. Generated images may contain
separately licensed components; the presence of an Apache-2.0 repository
license does not relicense those components.

Proprietary WD firmware, binaries, signing material, and device dumps are not
accepted into this repository. Hardware observations and independently written
interoperability code must be documented with their provenance.

The future mascot and other original artwork are not licensed by this policy
until an explicit artwork license is added.

This file describes the project's intended licensing structure; it is not
legal advice.

## Development source collection

The QEMU build runs Buildroot `legal-info` to collect package source archives,
applied patches, license texts, manifests and the build configuration. It then
retains the original Buildroot archive already authenticated by the build
driver at `legal-info/phantowd-build-inputs/buildroot-<version>.tar.xz` in the
build output directory. The collector verifies the pinned SHA-256 before and
after copying, refuses symlinked inputs/outputs and does not replace a different
existing archive. It does not download sources or change firmware images.

The upstream `legal-info/README` and its warnings are preserved, including its
warning that Buildroot itself did not save its source. The supplemental archive
addresses that particular missing input; it is not a complete corresponding-
source bundle or a legal-compliance determination. An exact project revision,
all Buildroot modifications, toolchain/package source coverage, configurations,
license notices and distribution obligations still require release review.
The collected tree stays in the build workspace; the current binary CI artifact
upload is not a publication of that source bundle.
