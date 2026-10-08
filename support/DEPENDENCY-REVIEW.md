<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors -->

# Dependency review and update qualification

## Scope of the 2026-10-07 review

This is a **partial advisory review**, not a vulnerability-free assertion or
release approval. It examines the local cached QEMU image built from
`d2320541dd67c56ad17c7a6bcaae38fe686be03f`, with unchanged API inputs at
documentation checkpoint `842a222d481e076776fbd00e91b3f4ee656fd273`.
It does not describe a newer public branch, all selected packages, physical
EX4 behavior or a supported installation.

All seven local artifact hashes were rechecked before using the inventory.
CycloneDX contains 80 components; `buildroot-show-info.json` contains 88
package records, including virtual packages, with 31 non-virtual target
records. These are different inventories, not interchangeable counts.

| Input | Observed version / scope | Review outcome |
| --- | --- | --- |
| Buildroot | 2025.02.18 build system | Still listed in the selected LTS line; individual packages require their own review |
| Linux and headers | Earlier advisory inventory: 6.18.54; current selected and locally rebuilt image: 6.18.55 | Authenticated source, complete cached ARMv5 integration and exact metadata/source/image audit pass; hosted/EX4/release gates remain |
| Samba | 4.22.11 target, six declared patches | Upstream's July security release; no complete Samba advisory/configuration review claimed |
| OpenSSL | 3.5.8 **host only**, four declared patches | September advisory requires evaluating an update to 3.5.9; affected host call paths remain unassessed |
| Go | 1.26.6 host SDK **and compiled target runtime** | 1.26.8 is a maintenance candidate, not a demonstrated security or QEMU-timeout fix |
| x/crypto | v0.57.0 target API module | Reviewed SSH records [6354](https://vuln.go.dev/ID/GO-2026-6354.json)/[6355](https://vuln.go.dev/ID/GO-2026-6355.json) are fixed at v0.56.0; this API uses Argon2, not an SSH server |
| x/sys | v0.48.0 target API module | Reviewed Windows record [5024](https://vuln.go.dev/ID/GO-2026-5024.json) is fixed at v0.44.0; this is not an ARMv5 exposure finding |
| BusyBox / util-linux | 1.37.0 / 2.40.4 target, 20 / 15 declared patches | Upstream base-version matching alone loses backport information; dispositions remain to be reviewed |
| glibc | 2.41-161-g5dd252cf1d113644b3679f5a158e9ef20217865e target | Review the exact stable-branch commit, not only the base 2.41 CPE |
| libtirpc / zlib / nfs-utils | 1.3.6 / 1.3.2 / 2.8.6 target | Inventoried; complete advisory review not performed |

Source facts: [Buildroot downloads](https://buildroot.org/download.html),
[kernel releases](https://www.kernel.org/releases.json),
[Samba 4.22.11](https://www.samba.org/samba/history/samba-4.22.11.html),
[OpenSSL September advisory](https://openssl-library.org/news/secadv/20260929.txt),
[Go release history](https://go.dev/doc/devel/release),
[Go database API](https://go.dev/doc/security/vuln/database).
Refresh these dated observations before choosing update inputs.

## Linux 6.18.55 focused qualification (2026-10-07)

The kernel.org archive was authenticated on its uncompressed tar stream with
the pinned stable-release signer. Its compressed SHA-256 is
`f410638061a165c12f42ab871d2f3fcd525515359b5faeee80969cff84524df9`.
`COPYING`, GPL-2.0 and Linux-syscall-note match the previously qualified
license hashes. The unchanged EX4 Stage B3 DTS compiles to byte-identical
DTBs against both authenticated source versions; existing warnings remain.
The generic research patch dry-run passes with zero fuzz, with a reported
binding-file offset. This is not resolved board Kconfig or hardware proof.

An actual Linux 6.18.55 QEMU kernel build uses the existing ARMv5 toolchain and
baseline resolved configuration. Every configuration symbol retains its
previous value, including ACL, RAID and no-MD-autodetection requirements.
Its standard ARMv5 smoke test passes with the original 240-second budget and
all original assertions, including the storage, identity, SMB and NFS fixtures.
Only the expected-kernel field was changed in a disposable rootfs copy:
the API and guest readiness script remain byte-identical to the base.
All seven original artifact hashes verify both before and after the test.
Sources, compilation and QEMU snapshot files live in bounded RAM scratch;
no new Docker image or named volume is created by this focused probe.

Two initial harness refusals are accounted for, not erased: read-only
`/var/tmp` prevented QEMU snapshot creation before guest execution; after
adding bounded tmpfs there, the guest correctly refused a 6.18.54 metadata /
6.18.55 running-kernel mismatch. Paused-QEMU and metadata readback controls
isolate those issues before the successful original smoke replay. Neither
refusal demonstrates a kernel regression; neither correction removes a check.

Current source pins now update all five firmware configurations/release files,
kernel/header archive hashes and the version-qualified GPL hash patch/driver
together. Version/workflow locks, kernel-input predicates, shell checks,
dashboard DOM tests and actual zero-fuzz GPL-patch application against the
authenticated original Buildroot recipe pass locally. The old image, headers,
SBOM and compiler metadata remain evidence only for their original build.
The later complete-image evidence below extends this focused scope; neither
proof establishes clean reproducibility, EX4 kernel build/boot or release
qualification. The hosted native timeout and physical-device safety gates
remain open.

## Linux 6.18.55 complete local qualification (2026-10-07)

The unchanged complete driver passes on frozen source
`fb2f68c6cded66db1a118c21fa99ca8fad2bfc6d`, API tree
`5d819e6b9ad72b849f2fb3c3c27c1b2c47a114ff`, using a newly initialized
configuration-derived output in the existing project workspace. The full
toolchain/kernel/header/userspace build, host ordinary/race/fixed fuzz,
standard smoke, MD comparisons, state reboot, launcher/runtime/loader/atomic,
all three original Samba campaigns and synthetic SMART lanes pass. No guest
deadline or assertion is relaxed and no previous output is adopted as 6.18.55.

The independent post-terminal read-only audit verifies all 935 tracked API
files against compiled package and collected source archive, rejects stale
extras and uses zero generated-marker exemptions. Declared licenses match;
configured stripping reproduces installed/image/exported API bytes. All seven
actual artifacts hash correctly. Kernel AND header package versions/namespaces,
source downloads, SBOM project/components, source/installed/image release and
non-flashability, output/export zImage/DTB/rootfs, exact legal manifest, BOTH
authenticated kernel source archives and six legal license copies agree.
The actual API confirms linked Go 1.26.6, CGO disabled, Linux/ARM/GOARM5.
Twenty-one regular-file witnesses are re-read unchanged; alias/generation drift
and special files refuse. Preparatory controls refuse the actual old image as
6.18.55 and duplicate metadata; they are not substituted for this final audit.

Selected artifact hashes:

| Artifact | SHA-256 |
| --- | --- |
| zImage | `870a75a25fc5de6126c049fcca85075d5cc7ba9c7f4a393ccf96da7fb42f3111` |
| rootfs.ext2 | `8f37bfa289f7e260853c20705bdcf6341beffded9c50986676501cb74899fb5d` |
| API source archive | `43f00ae652137031047933c0ece4117b2de01544dc5d05f9703d19876d02765d` |
| SHA256SUMS | `f972c23375ff1432cdc9c75ea9993e7cb867a6ac321c69cd0050419f7fe161eb` |

This is local complete integration in an existing development environment,
NOT independent clean reproduction, complete component/backport/CVE or release
licensing review, hosted-head or resolved EX4/physical qualification. Go and
host OpenSSL update packets remain separate. A successful local Samba run does
not demonstrate a fix for historical hosted timeouts or authorize deployment.

## Current cached integration requalification (2026-10-08)

Frozen `4ca65d557c746eec08d36dadf72a97bdcbce9757`, API tree
`677a3f8f76122ab310c5763d6cd0ee631ace4543`, passes the complete cached
host/ARMv5 driver and independent strict post-terminal audit. The normal driver
applies a four-job ceiling to all Buildroot parallel consumers. All original
guest campaigns, deadlines and assertions remain, including three Samba and
synthetic SMART lanes. Fixed phase diagnostics are QEMU-only, nonqualifying
observations; no timeout resolution or measured speedup is inferred.

The audit now matches exactly **937** tracked API sources against compiled
package and legal source archive, with zero stale extras/generated-marker
exemptions. All earlier license/strip/image/export, seven-artifact, kernel AND
header, metadata/SBOM/release, authenticated legal-source/license and linked-Go
checks pass, with 21 unchanged regular-file witnesses. The new source archive
SHA-256 is `0325799ef3ce9eca78a78141a8948e717d79b4a3ffb4c400ec0232ca414488f9`.
Normal product API and all seven final artifact hashes remain exactly those
above; the two new source files are QEMU-tagged diagnostics/tests. The earlier
935-input proof remains a historical observation, not the current census.

This cached pass does not re-run the complete advisory review, establish clean
reproducibility, waive failed hosted checks, qualify physical EX4 peripherals,
activate product services or authorize installation. Other dependency update
packets and all release gates remain separate.

## Important interpretation boundaries

- OpenSSL CVE-2026-84782 has a DTLS-specific path and is fixed in 3.5.9.
  This image's SBOM contains `host-libopenssl`, not target `libopenssl`.
  That does **not** establish a vulnerable NAS HTTPS listener, nor exempt the
  build environment from review. Record affected host applications/configuration
  before assigning an exposure disposition.
- `host-go-bin` being a host package does not make Go findings host-only:
  `go version -m` on the exported API confirms Go 1.26.6, CGO disabled,
  Linux/ARM/GOARM=5 and the two module versions above. Its standard library
  is part of the target executable. Module manifests alone do not prove this.
- The reviewed recent stdlib/toolchain records GO-2026-5026, 5942, 5972,
  6088–6091, 6218, 6179 and 6180 specify a 1.26-branch fix at 1.26.6.
  For example, inspect [the full HTTP record](https://vuln.go.dev/ID/GO-2026-6089.json).
  The module index can instead summarize a later 1.27 prerelease: inspect
  each record's full version ranges, not only its highest `fixed` field.
- Go 1.26.7 fixes issue [80927](https://github.com/golang/go/issues/80927),
  involving unencrypted HTTP/2 timeout handoff. The current API sets a nonzero
  `ReadTimeout` and does not enable unencrypted HTTP/2. That inspected issue
  does not establish the cause of the independent Samba/QEMU timeout.
- Buildroot's `ignore_cves` lists are upstream metadata, **not** our product
  waivers. BusyBox, util-linux and glibc have 9, 6 and 19 listed dispositions
  respectively in this inventory. Each needs an attributed patch/configuration
  rationale before a release-level security claim. No blanket suppression.
- Matching an upstream fixed version does not prove patch application, code
  reachability, exploit absence or complete advisory coverage. A CPE does not
  replace exact source/configuration and binary evidence.

## Required update work packets (M0.4)

1. **Linux 6.18.55 selected update:** review the
   [stable changelog](https://www.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.18.55),
   finish configuration-relevant change review and exact-head hosted, independent
   clean and EX4 profile qualification. The complete cached QEMU build/audit
   above now pass from authenticated, coherent kernel/header/hash consumers.
   They do not replace resolved EX4 configurations or device-write/thermal
   fences. A compile does not authorize a physical boot or disk operation.
2. **Host OpenSSL 3.5.9 candidate:** retain the Buildroot LTS baseline unless a
   concrete requirement calls for a branch change. Review its exact recipe and
   four patches, source/license hashes and host reverse dependencies. Qualify the
   actual host consumers and regenerated package/SBOM metadata. Do not add target
   OpenSSL merely to satisfy a scanner or expose new crypto services.
3. **Go 1.26.8 candidate:** authenticate the exact SDK/source inputs, update the
   Buildroot recipe without unpinned toolchain downloads and preserve the module
   vendor set. Run ordinary/race/fuzz checks and the original ARMv5 campaigns;
   verify the compiler version embedded in the exported API, source/license
   collection and image equality. Do not infer a speedup, drop revalidation or
   change test budgets to obtain a pass.
4. **Complete the review:** cover every selected host/target component and linked
   Go package, actual backport contents and disabled/compiled features. Record
   advisory ID, upstream affected/fixed ranges, source/patch identity, exact
   exposure rationale, reviewer/date and unresolved actions. Distinguish fixed,
   not affected, mitigated and unassessed; revisit on dependency/config changes.

Perform focused local validation before one necessary complete integration run.
Keep only the existing project cache volumes; no broad Docker cleanup or
repeated hosted reruns. Publish an updated SBOM and source/license bundle only
from the exact qualified candidate. The Linux pin changes above do not change
service activation, installation claims or hardware authorization.
