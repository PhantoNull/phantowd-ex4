# Read-only volume metadata helper

This small Linux helper uses libblkid's low-level safe-probe API on **one
caller-supplied read-only descriptor on stdin**. It accepts no path or other
arguments, opens no user-selected path and does not enumerate devices. The
descriptor must reference a regular image or block object and have O_RDONLY
access (not O_PATH). A future trusted broker must establish which object may
be opened, retain its identity, provide a clean process environment and collect
the result with a deadline. No such broker or HTTP operation exists yet.

The implementation enables superblock and partition signature probing without
type/usage filters, so filtering does not hide competing RAID/crypto/other
signatures. It uses no cache, UUID/label lookup, mounting, assembly, repair,
formatting or update operation. It requests no partition-entry details or
topology chain. This probes unmounted regular test images now; it does not
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
or protect against all concurrent writers. A future broker needs process-group
supervision, complete eligible-device discovery and ambiguity handling.

## Build and tests

The opt-in Buildroot package selects **libblkid only**, not util-linux's basic
program suite. It is not enabled in the default QEMU image yet. The package
source is Apache-2.0; libblkid and dependencies keep their upstream licenses
and require normal Buildroot legal-info/SBOM handling.

`support/container/test-volume-probe.sh SOURCE_DIR UTIL_LINUX_ARCHIVE` builds
host libblkid from the hash-checked Buildroot 2025.02.18 archive (util-linux
2.40.4), then compiles with strict warnings/hardening and runs generated
regular-image tests. Run it in the existing development container, with
read-only sources/archive, a disposable executable /tmp, no network, no
privileged mode and no forwarded devices. Tests create ext2/3/4, blank, swap
and zero-UUID images, verify expected classifications and unchanged data hashes,
and reject writable descriptors, pipes and unexpected arguments.

Initial evidence is host-native only. ARMv5 package build, actual ambiguous
signature fixture, QEMU block-device execution, fault injection and discovery
integration remain required. This is not WD-layout, migration or physical
storage qualification; do not use it on production disks at this stage.

Contracts: upstream [low-level libblkid probing](https://www.kernel.org/pub/linux/utils/util-linux/v2.40/libblkid-docs/libblkid-Low-level-probing.html)
and [blkid safe-probe behavior](https://man7.org/linux/man-pages/man8/blkid.8.html).
