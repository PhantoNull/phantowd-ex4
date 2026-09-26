# Read-only volume metadata helper

This small Linux helper uses libblkid's low-level safe-probe API on **one
caller-supplied read-only descriptor on stdin**. It accepts no path or other
arguments, opens no user-selected path and does not enumerate devices. The
descriptor must reference a regular image or block object and have O_RDONLY
access (not O_PATH). The [Linux supervisor](../phantowd-api/volumeprobe/README.md)
now supplies a minimal process environment, single-slot scheduling, bounded
output, deadline/cancellation, descriptor rechecks and strict response decoding.
A future trusted broker must still establish which object may be opened,
exclusive access and complete identity discovery. No such broker or HTTP
operation exists yet.

The implementation enables superblock and partition signature probing without
type/usage filters, so filtering does not hide competing RAID/crypto/other
signatures. It uses no cache, UUID/label lookup, mounting, assembly, repair,
formatting or update operation. It requests no partition-entry details or
topology chain. Tests probe unmounted regular images and QEMU block objects; it does not
authorize mounting media to learn its identity.

## Result contract

One bounded JSON object has schema version 1, a source kind and status:

- `ext-metadata`: libblkid recognized ext2/3/4, filesystem usage, no partition
  table result and a nonzero 128-bit UUID. Type/UUID are returned.
- `other-signature`: another recognized usage/type or a partition table.
- `unusable-signature`: ext-family signature but no usable UUID.
- `ambiguous`: libblkid's safe-probe reports competing signatures.
- `unidentified`: no identifying result. This does **not** mean empty, healthy,
  readable in full, safe to erase or available for automatic provisioning.

The pinned util-linux 2.40.4 `blkid_do_safeprobe` implementation maps negative
chain results to generic `-1`, including an internal ambiguous `-2`. With
this baseline, a tested ext2/XFS signature collision therefore produces a
nonzero helper exit **without JSON**, not the `ambiguous` status. Callers must
reject it; they must not infer no signature, retry with a type filter, or
reinterpret arbitrary I/O errors as proven ambiguity. The explicit status is
reserved for backends that preserve `-2` and is not exercised by this baseline.
Safe probing also gives RAID/crypto signatures precedence instead of reporting
every overlapping filesystem; those are rejected as `other-signature` here.

All responses hard-code `mount_performed`, `compatibility_qualified` and
`activation_allowed` to false. Other statuses return empty type/UUID strings;
there is no candidate selection or mount authorization. Process errors yield
nonzero exit and a generic diagnostic, not a successful metadata result.
UUIDs are internal identity data, not public diagnostics. Labels and arbitrary
library output are never printed. Output values are fixed literals or a
validated UUID, not interpolated untrusted metadata.

The helper caps address space at 64 MiB, CPU at two seconds, core dumps at zero,
sets no-new-privileges and a five-second alarm. These are defensive limits,
**not** a seccomp sandbox, a guarantee against kernel uninterruptible I/O, or
permission to run as a privileged public service. It compares descriptor
metadata before/after the probe; this does not provide an atomic disk snapshot
or protect against all concurrent writers. The supervisor is not a sandbox;
a future broker still needs complete eligible-device discovery, exclusive
access and ambiguity handling.

## Build and tests

The Buildroot package selects **libblkid only**, not util-linux's basic
program suite. It is enabled only in the QEMU development profile. The package
source is Apache-2.0; libblkid and dependencies keep their upstream licenses
and require normal Buildroot legal-info/SBOM handling.

`support/container/test-volume-probe.sh SOURCE_DIR UTIL_LINUX_ARCHIVE PATCH_DIR HOST_BIN` builds
host libblkid from the hash-checked Buildroot 2025.02.18 archive (util-linux
2.40.4) and digest-verified Buildroot package patches. It regenerates build
inputs with the baseline host autoreconf tools, then compiles with strict
warnings/hardening and runs generated
regular-image tests. Run it in the existing development container, with
read-only sources/archive, a disposable executable /tmp, no network, no
privileged mode and no forwarded devices. Tests create ext2/3/4, blank, swap
and zero-UUID images, verify expected classifications and unchanged data hashes,
and reject writable/O_PATH/directory descriptors, pipes and unexpected arguments.
A generated XFS v4 probe header is recognized alone but conflicts with a fresh
ext2 superblock; that collision must fail without JSON and without changing
the image hash. Invalid XFS geometry must not identify a filesystem. These
headers are parser fixtures, not valid mountable XFS filesystems.

The fast QEMU lane cross-compiles a static ARMv5 helper from that same archive
with the same patch set and injects it into a disposable base-image copy. Before mounting either test
disk, the guest checks their fixed synthetic VPD identities, exact device
numbers and absence from its mount inventory, then passes read-only descriptors
to the helper. Both ext2 UUID results and an unidentified regular-file result
have passed. The helper does not choose which disk to use or grant activation.

Clean Buildroot package/library/license integration, ARMv5 collision/error
coverage, I/O fault injection and trusted complete-device discovery
remain required. Static injection is not a release build and its library is
not described by the base artifact's SBOM. This is not WD-layout, migration or physical
storage qualification; do not use it on production disks at this stage.

Contracts: upstream [low-level libblkid probing](https://www.kernel.org/pub/linux/utils/util-linux/v2.40/libblkid-docs/libblkid-Low-level-probing.html)
and [blkid safe-probe behavior](https://man7.org/linux/man-pages/man8/blkid.8.html).
