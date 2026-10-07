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
| Linux and headers | 6.18.54 target | 6.18.55 is an update candidate, not yet built or qualified here |
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

1. **Linux 6.18.55 candidate:** review the
   [stable changelog](https://www.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.18.55),
   authenticate the archive/signature with the pinned kernel signer, then update
   all kernel/header/hash consumers coherently. Recheck QEMU and EX4 profile
   configurations, especially existing device-write/thermal fences. A compile
   does not authorize a physical boot or disk operation.
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
from the exact qualified candidate. This review changes no pins, image bytes,
service activation, installation claims or hardware authorization.
