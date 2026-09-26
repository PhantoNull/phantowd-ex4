# Fast API and file-service integration checks

`container/test-qemu-api-overlay.sh` is an optional developer feedback lane.
It rebuilds the Go API with the pinned compiler and injects it, the current
guest readiness script, the NFS fixture helper and the x/sys license into a
**temporary copy** of a previously built QEMU filesystem. The original
artifact is never modified. This is not a firmware builder or an installer.

Use the existing pinned development container with:

- no network, privileged mode, host devices or forwarded ports;
- source, the exact CI base artifact directory and compiler mounted read-only;
- an executable, disposable writable `/tmp` (the container root can be read-only);
- the existing `qemu-system-arm`, `debugfs`, `mkfs.ext2` and Go tools.

Inside that container, the invocation is:

```sh
sh /src/support/container/test-qemu-api-overlay.sh \
    /base /toolchain/bin/go /src
```

Here `/base` is one complete `phantowd-qemu-armv5` artifact from an exact,
trusted successful project CI run; `/toolchain/bin/go` is the actual pinned
Linux compiler path supplied by the operator, not a downloaded latest compiler.
Record the run, commit and toolchain when reporting results. The helper checks
the base's SHA256SUMS for integrity; this does not authenticate an arbitrary
download. It refuses special files/symlinks for the principal image inputs.

The normal QEMU smoke driver additionally creates a fresh 16-MiB ext2 data
image with a fixed **test-only** UUID and synthetic SCSI serial/WWN. Both disks
use QEMU snapshot mode. The guest verifies the synthetic data-disk identifiers
before mounting it; it never formats a guest block device. The host driver
removes only its own temporary data image after QEMU exits. The API observer
remains read-only; fixture mutations are in a separate QEMU-only test path.

The NFS fixture renders three policies, applies them with the actual target
`exportfs`, and checks mounted/unmounted access, an escaped path, a synced
write and server-side UID/GID/content, server-side read-only denial, and an
unlisted-client denial. Mount requests have a Go-enforced deadline and bounded
retry settings; absence of a helper or a timeout is not a successful denial.
Cleanup revokes generated exports and retries ordinary unmounts with a bounded
guest-only export-cache flush. This is not product service orchestration.

## Evidence boundary

This lane can exercise current userspace against the base's kernel and
packages without rebuilding Buildroot. It does **not** validate changed
kernel, Buildroot, package selections, libraries, complete overlay installation,
license packaging, SBOM regeneration or reproducibility. Files in the old
artifact's SBOM describe the base, not the injected copy. No generated image
from this lane may be published as a release or staged on an EX4.

Clean Buildroot/CI qualification is still required before merge/release. QEMU
does not qualify physical SATA, WD layouts, cooling, NAND or device recovery.
