# Fast API and file-service integration checks

`container/test-qemu-api-overlay.sh` is an optional developer feedback lane.
It rebuilds the Go API with the pinned compiler and injects it, the current
broker mdev rule, guest readiness script, NFS fixture helper and x/sys license
into a **temporary copy** of a previously built QEMU filesystem. The original
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

For repeated local API-only iterations, the same overlay runner accepts two
opt-in environment flags:

```sh
PHANTOWD_QEMU_OVERLAY_REUSE_BASE_VOLUME_PROBE=1 \
PHANTOWD_QEMU_OVERLAY_SMOKE_ONLY=1 \
sh /src/support/container/test-qemu-api-overlay.sh \
    /base /toolchain/bin/go /src \
    /downloads/util-linux-2.40.4.tar.xz \
    /toolchain/bin/arm-buildroot-linux-gnueabi-gcc \
    /buildroot-2025.02.18/package/util-linux
```

The first flag verifies and reuses the volume-probe helper already inside the
trusted base artifact. It rejects the obsolete schema-v1 helper, but that
schema check is not provenance or byte-for-byte source verification; reuse it
only when the helper source and patch set are unchanged. Otherwise leave it
disabled so the helper is rebuilt from pinned sources.
The second omits the separate two-boot state-persistence fixture and runs only
the single-boot smoke. Both default to `0`, so the ordinary invocation still
rebuilds/injects the helper and runs both fixtures. This fast mode is local
feedback only and cannot qualify storage-helper changes, reboot persistence,
or the complete Buildroot output.

The normal QEMU smoke driver additionally creates a fresh 16-MiB ext2 data
image with a fixed **test-only** UUID and synthetic SCSI serial/WWN, plus a
read-only clone with distinct synthetic device identifiers. All virtual disks
use QEMU snapshot mode. The guest verifies the synthetic data-disk identifiers
before mounting it; it never formats a guest block device. The host driver
removes only its own temporary data image after QEMU exits. The API observer
remains read-only; fixture mutations are in a separate QEMU-only test path.

The smoke attaches two temporary 32-MiB read-only GPT disks with identical
partition tables and identifiers, but distinct virtual-device VPD identities.
Their one partition has a fixed test-only disk GUID and PARTUUID, no filesystem,
and is never mounted. The ARMv5 self-test reconciles each parsed disk GUID,
PARTUUID, partition number, start/size and GPT type GUID against the complete
generation-bound sysfs inventory, then classifies the cloned identifiers as
ambiguous. It also checks a conservative generic hint (`linux-data`) for the
declared GPT type GUID. This describes neither bytes stored in the partitions
nor any WD/EX4 role or compatibility.
Only GPT is currently accepted for this private identity observation. DOS/MBR
is explicitly unsupported and its disk/partition IDs are discarded. The
correlation struct is excluded from JSON serialization; no raw disk GUID,
PARTUUID, geometry, kernel name or path is an API field. The marker
`PHANTOWD_PARTITION_SYSFS_CORRELATION_READY` is fixture evidence only.
The self-test uses both complete candidate-set GPT observations directly; it
requires duplicate disk GUID and PARTUUID statuses to be ambiguous independently
while their sysfs generations remain distinct. The marker
`PHANTOWD_PARTITION_IDENTITY_CLASSIFICATION_READY` reports the complete-set
coverage (`observed_gpt_disks=2`, `coverage=partial`) and the cloned guest pair.
Host tests additionally exercise duplicate disk GUID/PARTUUIDs across two
candidates admitted by complete discovery, plus disk-only and PARTUUID-only
collisions. MBR and no-table candidates are coverage
gaps, not proof of uniqueness. The private singleton/ambiguous labels are not
serialized; only aggregate duplicate counts are returned by the separate manual
observation endpoint. The smoke-only M3.2a API check sends one authenticated,
CSRF-protected POST through the running ARMv5 API to the real guest broker. It
requires two cloned GPT disks/partitions and duplicate counts in the summary,
verifies raw identifiers, partition geometry, kernel names and paths are absent
from HTTP, and confirms the ordinary storage response remains redacted. It
uses only disposable read-only synthetic GPT disks and never mounts/imports/
writes. This exercises the current
API/helper overlay on the cached kernel/package base; it is not a clean
Buildroot, two-boot, hosted-CI or EX4 qualification. The observation is not
persisted or used to mount/import.

The read-only storage collector also requires nonzero, unique kernel `diskseq`
values for whole-disk entries, rechecks each value around its local observation,
and rechecks the block-node name set and generations before returning. The
generation is not exposed as a durable identity or returned in API JSON. Host
fixtures exercise changes during collection; a stable QEMU smoke exercises the
normal path but does not emulate hotplug races or qualify physical SATA/libata.

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

Current local follow-up (2026-09-29; not yet pushed): Buildroot Samba now has
Jansson-backed JSON enabled without AD-DC. The QEMU fixture validates complete
session server IDs and uses PID/unique_id for smbcontrol, with no PID-only
fallback. The current marker confirms two target sessions removed and an
unrelated same-IP reader preserved. The owner-approved contract combines
account disable and session revocation; uncertain revocation enters review
without retry. This remains fixture-only. Open handles and reconnect/durable
handles remain unqualified.

Historical pre-JSON characterization (superseded): an earlier disposable
fixture showed that disabling an account alone did not revoke existing SMB
sessions, and used PID-only `smbcontrol` as a test stimulus. Its old
`--without-json` and PID-only limitations do not describe the current fixture.

The Owner-managed M2.4 enrollment fixture additionally routes one explicit
revision-checked enable through the local test socket: valid authentication is
denied while disabled, accepted after same-SID confirmation, and empty-password
authentication remains denied. This is QEMU-only behavior, not product startup
or HTTP authorization.

These checks cover one generated policy and a simple Unix-mode layout. They
do not qualify POSIX ACL provisioning/inheritance, Windows ACL editing,
cross-protocol consistency, arbitrary migrations, missing-volume recovery or
a production volume resolver. Retained guest-only logs/data disappear with
the disposable QEMU snapshots.

The same mounted disposable disk hosts a separate descriptor-guard fixture.
It creates private bind mounts and exercises unique mount-ID/inode/device/type
matching, safe descendant directory opens, symbolic-link and traversal
refusal, nested bind refusal, read-only transitions and rejection of a second
mount of the same disk/root over the anchor. An identity/state mismatch
permanently closes the existing guard; after the original anchor reappears,
only a fresh tuple and new guard are accepted. After ordinary unmount the
fixture verifies that the guard does not accept the underlying system
directory. All references and private mounts are released before the original
data volume is unmounted.
The kernel UUID ioctl must match the known mkfs UUID; a different expected
UUID is refused on the same mount. The guard opens no block node and does not
read directory listings or file contents. This is not unmounted-filesystem
discovery, clone detection or a complete service activation lease; descriptors
already returned to callers are not revoked by the guard;
see the [guard contract](../src/phantowd-api/mountguard/README.md).

A separate read-only virtual clone of the fresh data image carries the same
filesystem UUID on a different SCSI device. The fixed guest fixture verifies
its synthetic VPD identity before mounting it read-only, detects the UUID
conflict across supplied mounted roots, distinguishes the original disk's bind
alias and rejects an incomplete scan. It unmounts the clone normally. This
does not prove completeness of product disk discovery or WD compatibility.

The smoke also creates two fresh 32 MiB sparse raw files and attaches them as
the only members allowed by a QEMU-only MD fixture. Inside the snapshot-mode
guest, fixed-identity checks precede `mdadm` RAID1 creation and ext2 formatting;
the synthetic filesystem is mounted read-only. The test verifies live sysfs
member links and MD health, mountinfo read-only state, descriptor-guard UUID
and mount identity, attribution of the mount to both backing disks (not an
unrelated disk), then ordinary unmount and array stop. The shell trap removes
only those two files from its private temporary directory. MD RAID1, mdadm and
e2fsprogs are enabled only in the QEMU profile; the EX4 profile is unchanged.
All guest writes are isolated by QEMU snapshot mode. This exercises a real
guest MD stack, not device-mapper, product array discovery, a global exclusivity
proof, or EX4 storage compatibility. The exact-head run for this fixture must
emit `PHANTOWD_MOUNT_GRAPH_READY`; until that run passes, this paragraph
documents the intended test rather than completed evidence.

### MD v1.0 writer-to-host-parser fixture

On Windows, run `support/test-qemu-md-v10.ps1` for a focused check of the
offline MD v1.0 parser. It requires the already-present pinned Docker image,
Buildroot workspace/cache, QEMU base artifact, toolchain and util-linux source
archive; it uses `--pull never`, mounts the repository/base/cache read-only,
disables networking, and does not create persistent images or volumes. The
ephemeral container uses `/tmp` tmpfs for generated files and is removed on
exit. It rebuilds only the API, the static volume-probe fixture helper and the
host parser from current source into a temporary copy of the base rootfs.

The guest uses a snapshot-backed root disk and exactly two writable 32 MiB
raw member files in tmpfs, attached with fixed synthetic SCSI identities. The
bounded QEMU-only entry point asks ARMv5 `mdadm` to create a two-member RAID1
with metadata 1.0, verifies array/member topology, stops it, and reboots. The
host then invokes `phantowd-lab inspect-md-v1.0-component` on each regular
component image. The harness checks valid checksums, a shared redacted array
fingerprint, distinct member fingerprints, active roles 0/1, unchanged member
hashes, and an unchanged base rootfs hash. It never formats a filesystem,
mounts, imports, assembles on the host, reads a NAS/physical disk, or writes
NAND/MTD. The two member files and reports are removed from the private temp
directory by the test trap.

The local fixture passed on 2026-09-30 using cached Linux 6.18.53 ARMv5 QEMU
artifacts. This is a generic parser-agreement test only; it does not establish
EX4 hardware, WD metadata, migration, recovery or compatibility qualification.
It is also not a clean Buildroot/SBOM/legal-info rebuild or hosted CI result.

## Evidence boundary

### Separate state-persistence boots

After the normal smoke, both the fast lane and clean Buildroot runner execute
`support/qemu-state-reboot.sh`. It creates a new 16 MiB regular-file ext2 disk,
starts two independent ARMv5 kernels and retains only that generated data disk
between them. Each root disk is separately snapshotted; no NIC is attached.
Only guest loopback is raised for the HTTP/HTTPS and Samba state fixtures.
A dedicated PID-1 script skips all normal services and accepts only fixed seed
and verify phases. Compiled machine/VPD/device/UUID checks precede the writable
mount; the expected mounted identity is verified before touching configuration.

The seed phase commits complete desired share policies, then leaves a valid
pending revision and a separate deliberately corrupt fixture. Verification
requires the exact committed policy, refusal of stale revisions and corrupt
state, no automatic pending-file promotion, and a successful subsequent commit.
Both phases ordinarily unmount before rebooting. Logs require both phase markers
and kernel restart messages. A timeout or missing marker fails the lane.

A separate directory holds combined SMB/NFS policy saved through the actual
development HTTP adapter. Each phase starts ephemeral loopback HTTP and HTTPS
servers, with a synthetic administrator session and test certificate. The
fixture checks unauthenticated and missing-CSRF refusal, strict TLS cookie
naming, full revision commits, replay conflicts, GET and explicit store reopen.
The second kernel must recover the exact policy and commit subsequent revisions.
`PHANTOWD_SERVICE_HTTP_READY` is required in the verification log. Nothing is
forwarded to the host; this policy API never activates services.

Administrator fixtures cover both native version-2 state and the exact former
prototype version-1 encoding (not WD accounts). The seed enters the real
authenticated password-change handler, verifies session revocation and leaves
an uncommitted pending document. The independent second kernel must retain the
committed replacement, reject the old password and permit login/session lookup
with the new one. `PHANTOWD_PASSWORD_REBOOT_READY` is required. The normal smoke
also requires a real guest-loopback HTTPS password change and old/new login
checks, separately from the persistent-disk handler test.

A separate fixed Samba fixture in the same two boots copies only the generated
guest's `/etc` to private test storage on the first boot, then bind-mounts that
copy for account operations. Both kernels require the fixture user to be absent
from their initial, fresh root image. The seed reserves a native UID/private GID,
creates its no-home/no-login Unix identity, rotates its test SMB password and
disables it. Samba's private/state databases persist alongside the account files;
lock/cache/PID directories and client auth files stay in guest RAM. No password
or account creation occurs on the second boot. Real SMB3 clients must observe
ACCOUNT_DISABLED before explicit re-enable, then reject the old password and
read/write using the retained password with unchanged Unix IDs and original data.
Account-file hashes, file inode/content/mode/ownership and loopback-only listeners
are checked. `PHANTOWD_SMB_REBOOT_READY` is required after daemon cleanup. The
fixture stops its own Samba instance, syncs the generated filesystem and releases
its mounts; it neither changes the base root image nor the default service profile.

This demonstrates clean-reboot persistence on the generated ext2 filesystem,
not crash/power-cut recovery, EX4 state provisioning, production account management,
WD configuration migration or a production-qualified writable management API. The temporary disk is discarded
afterward. Clean CI retains `qemu-state-reboot.log` with its validation artifacts.

Qualification caveat: intermittent local seed runs have reported `EBUSY`, first
during password-change development and again during identity-owner development.
The latest recurrence is specifically **state-volume unmount**, after the main
identity scenario passed. Subsequent full runs and ten additional two-boot
cycles passed; failure-only process/descriptor probes and a parent-exit probe
did not establish the cause. Temporary probes were removed. The cause remains
unproven, not fixed by the separate identity-channel overload correction.
Cleanup labels state-volume,
Samba-data and copied-`/etc` unmount failures, and a host regression checks that
the state-persistence fixture releases its own descriptors. Neither lazy
unmounts nor automatic retries mask failures. Investigate any recurrence;
successful clean-reboot runs do not establish crash or shutdown robustness.

### Qualification limits

This lane can exercise current userspace against the base's kernel and
packages without rebuilding Buildroot. It does **not** validate changed
kernel, Buildroot, package selections, libraries, complete overlay installation,
license packaging, SBOM regeneration or reproducibility. Files in the old
artifact's SBOM describe the base, not the injected copy. No generated image
from this lane may be published as a release or staged on an EX4.

Clean Buildroot/CI qualification is still required before merge/release. QEMU
does not qualify physical SATA, WD layouts, cooling, NAND or device recovery.
