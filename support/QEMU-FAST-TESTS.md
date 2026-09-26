# Fast API and file-service integration checks

`container/test-qemu-api-overlay.sh` is an optional developer feedback lane.
It rebuilds the Go API with the pinned compiler and injects it, the current
guest readiness script, the NFS fixture helper and the x/sys license into a
**temporary copy** of a previously built QEMU filesystem. The original
artifact is never modified. This is not a firmware builder or an installer.
It also cross-compiles and injects a static ARMv5 volume-probe helper using
hash-checked util-linux 2.40.4 sources, the exact Buildroot package patch set
(including libblkid partition-probing fixes), and the pinned Buildroot toolchain.

Use the existing pinned development container with:

- no network, privileged mode, host devices or forwarded ports;
- source, the exact CI base artifact directory and compiler mounted read-only;
- an executable, disposable writable `/tmp` (the container root can be read-only);
- the existing `qemu-system-arm`, `debugfs`, `mkfs.ext2` and Go tools.

Inside that container, the invocation is:

```sh
sh /src/support/container/test-qemu-api-overlay.sh \
    /base /toolchain/bin/go /src \
    /downloads/util-linux-2.40.4.tar.xz \
    /toolchain/bin/arm-buildroot-linux-gnueabi-gcc \
    /buildroot-2025.02.18/package/util-linux
```

Here `/base` is one complete `phantowd-qemu-armv5` artifact from an exact,
trusted successful project CI run; `/toolchain/bin/go` is the actual pinned
Linux compiler path supplied by the operator, not a downloaded latest compiler.
The final arguments supply the cached util-linux source archive, target C
compiler and util-linux patch directory from that trusted Buildroot baseline.
All must be mounted read-only. The helper verifies the patch-set digest before
applying it to a temporary extraction and running the baseline host autoreconf
tools beside the target compiler. Mount that baseline at its original build
path too if those tools contain absolute installation paths. Fixture-only
configure options still differ from the full Buildroot package environment.
Record the run, commit and toolchain when reporting results. The helper checks
the base's SHA256SUMS for integrity; this does not authenticate an arbitrary
download. It refuses special files/symlinks for the principal image inputs.

The normal QEMU smoke driver additionally creates a fresh 16-MiB ext2 data
image with a fixed **test-only** UUID and synthetic SCSI serial/WWN, plus a
read-only clone with distinct synthetic device identifiers. All virtual disks
use QEMU snapshot mode. The guest verifies the synthetic data-disk identifiers
before mounting it; it never formats a guest block device. The host driver
removes only its own temporary data image after QEMU exits. The API observer
remains read-only; fixture mutations are in a separate QEMU-only test path.

Before the first data-disk mount, a fixed guest fixture passes both unmounted
devices to the metadata helper through O_RDONLY descriptors. It checks exact
device numbers and the absence of both devices from the mount inventory before
and after probing. Both must return the known ext2 UUID; a separate blank
regular file must return unidentified, never an empty/safe-to-provision claim.
This validates helper execution, not a product device-selection broker.
The fixture also probes both descriptors together with an alias of the first:
the cloned UUID must conflict across the two distinct objects, while a set
containing only aliases must report one object. An unobserved UUID must remain
unobserved. These point-in-time sets do not establish discovery completeness.

The NFS fixture renders three policies, applies them with the actual target
`exportfs`, and checks mounted/unmounted access, an escaped path, a synced
write and server-side UID/GID/content, server-side read-only denial, and an
unlisted-client denial. Mount requests have a Go-enforced deadline and bounded
retry settings; absence of a helper or a timeout is not a successful denial.
Cleanup revokes generated exports and retries ordinary unmounts with a bounded
guest-only export-cache flush. This is not product service orchestration.

While this disk is mounted, a QEMU-only Samba fixture renders two shares using
the product renderer and starts a separate smbd on test port 1445. Its state,
passdb and PID/lock directories are separate from the baseline guest service.
Three temporary Unix users in one test group distinguish a writable grant,
a read-only grant and a user excluded from the share. The fixture checks
written content/Unix ownership, reader access, denied reader writes, excluded
users, bad credentials, a Unix-denied folder despite an SMB writable grant,
and refusal to read a symlink target outside the share. It checks no denied
write/download artifact appeared. Expected server refusal codes and a failed
client exit are required; timeout or missing tools are not successful denials.

The helper refuses non-ARMv5/non-Versatile PB machines, non-root invocation,
wrong synthetic data-disk identifiers and a missing/mismatched writable test
mount. Account names/IDs, paths and commands are fixed, not API inputs.
Credentials are public disposable fixture values passed through stdin/private
auth files, not product credentials. Cleanup stops and reaps the separate
daemon process group, removes only the created Unix accounts/group, then lets
the NFS fixture unmount the disk. No production account/lifecycle API is added.

These checks cover one generated policy and a simple Unix-mode layout. They
do not qualify POSIX ACL provisioning/inheritance, Windows ACL editing,
cross-protocol consistency, arbitrary migrations, missing-volume recovery or
a production volume resolver. Retained guest-only logs/data disappear with
the disposable QEMU snapshots.

The same mounted disposable disk hosts a separate descriptor-guard fixture.
It creates private bind mounts and exercises unique mount-ID/inode/device/type
matching, safe descendant directory opens, symbolic-link and traversal
refusal, nested bind refusal, read-only transitions and rejection of a second
mount of the same disk/root over the anchor. After ordinary unmount it verifies
that the guard does not accept the underlying system directory. All references
and private mounts are released before the original data volume is unmounted.
The kernel UUID ioctl must match the known mkfs UUID; a different expected
UUID is refused on the same mount. The guard opens no block node and does not
read directory listings or file contents. This is not unmounted-filesystem
discovery, clone detection or a complete service activation lease;
see the [guard contract](../src/phantowd-api/mountguard/README.md).

A separate read-only virtual clone of the fresh data image carries the same
filesystem UUID on a different SCSI device. The fixed guest fixture verifies
its synthetic VPD identity before mounting it read-only, detects the UUID
conflict across supplied mounted roots, distinguishes the original disk's bind
alias and rejects an incomplete scan. It unmounts the clone normally. This
does not prove completeness of product disk discovery or WD compatibility.

## Evidence boundary

### Separate state-persistence boots

After the normal smoke, both the fast lane and clean Buildroot runner execute
`support/qemu-state-reboot.sh`. It creates a new 16 MiB regular-file ext2 disk,
starts two independent ARMv5 kernels and retains only that generated data disk
between them. Each root disk is separately snapshotted; networking is absent.
A dedicated PID-1 script skips all normal services and accepts only fixed seed
and verify phases. Compiled machine/VPD/device/UUID checks precede the writable
mount; the expected mounted identity is verified before touching configuration.

The seed phase commits complete desired share policies, then leaves a valid
pending revision and a separate deliberately corrupt fixture. Verification
requires the exact committed policy, refusal of stale revisions and corrupt
state, no automatic pending-file promotion, and a successful subsequent commit.
Both phases ordinarily unmount before rebooting. Logs require both phase markers
and kernel restart messages. A timeout or missing marker fails the lane.

This demonstrates clean-reboot persistence on the generated ext2 filesystem,
not crash/power-cut recovery, EX4 state provisioning, account credentials,
schema migration or a writable management API. The temporary disk is discarded
afterward. Clean CI retains `qemu-state-reboot.log` with its validation artifacts.

### Qualification limits

This lane can exercise current userspace against the base's kernel and
packages without rebuilding Buildroot. It does **not** validate changed
kernel, Buildroot, package selections, libraries, complete overlay installation,
license packaging, SBOM regeneration or reproducibility. Files in the old
artifact's SBOM describe the base, not the injected copy. No generated image
from this lane may be published as a release or staged on an EX4.

Clean Buildroot/CI qualification is still required before merge/release. QEMU
does not qualify physical SATA, WD layouts, cooling, NAND or device recovery.
