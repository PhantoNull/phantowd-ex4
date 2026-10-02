# Fast API and file-service integration checks

## Fixed Samba ELF loader differential

`support/test-runtime-loader.ps1` is a local fast lane using only an existing
pinned image/workspace and manifest-verified QEMU base. It never pulls/builds an
image or creates a volume. Source, target and base are mounted read-only; the
rootfs copy lives in bounded 512 MiB tmpfs, while QEMU snapshots have separate
128 MiB temporary space. The compiler cache is removed before copying rootfs.
No network, host devices or forwarded ports are provided.

The host candidate fixes `usr/sbin/smbd`; it cannot select another program.
The generated PID1 has an explicit executable inode, mounts only temporary
runtime filesystems, checks each selected ELF SHA-256 and alias's canonical
target against the guest image, then invokes its actual ARMv5 glibc loader
with an empty environment and `--inhibit-cache --list`. It refuses an existing
`ld.so.preload`. This lists dependencies **without starting the Samba daemon**.
The host requires the exact candidate dependency roster, ordered unique success
markers and no unknown/failed resolution; a guest failure retains diagnostics.
There is one boot, no retry, a finite 90-second timeout, a read-only snapshot
root device and unchanged original-rootfs verification.

Local tests on 2026-10-02 passed with both the default builder and UID/GID 1000.
The real loader resolved 104 dependencies, matching 105 candidate ELF objects
including the main executable (27,110,832 bytes). Seven host tests cover
missing/extra/unknown resolutions, marker failures, conflicting aliases,
unsafe paths, budgets and temporary-space/cleanup contracts. Parser lint,
shellcheck, existing 13 feedback contracts and workflow path tests also pass.
This is cached overlay evidence, not a fresh Buildroot/hosted run, signed
runtime manifest, NSS/dlopen/privilege qualification or physical EX4 test.

The full Buildroot lane runs the same comparison after producing/verifying
its artifact set, and fast refusal tests run before the expensive compilation.
The candidate CLI itself remains host-only and never executes an ELF; only
this separately scoped fixture invokes the known public Buildroot loader.

## Smoke duration and cache scope

The complete one-boot smoke now has a **240-second** polling budget, not the
older 120 seconds. `PHANTOWD_QEMU_SMOKE_TIMEOUT_SECONDS` may explicitly select
1..300 canonical whole seconds; invalid values fail before creating fixtures.
The harness prints bounded progress every 30 polls. It still starts QEMU once,
fails immediately on a guest error/death, requires every existing readiness
assertion and retains its finite timeout/cleanup; it does not retry tests.

A local CPU-limited differential on an unchanged manifest-verified base
reproduced timeout at 121 seconds with the old budget and completed the full
smoke at 162 seconds with the new budget. This supports a resource-dependent
budget issue, not proof that every historical hosted failure has that cause.
Exact-head hosted qualification remains separate.

CI prefers the exact input/week compiler-cache key, then older keys for those
inputs, then the older QEMU/Linux compiler-cache namespace. It never restores
a prebuilt workspace/image or skips compilation/tests. The pinned Buildroot
wrapper hashes GCC configuration/source inputs for compiler identity, and
[ccache 4.10.2](https://ccache.dev/manual/4.10.2.html#_how_ccache_works) compares
compilation inputs before reusing results. Cache writes still require a fresh
completed-compile checkpoint on a non-cancelled trusted develop push; the
existing 1 GiB bound remains. A broader cache lookup does not demonstrate
speedup, independent reproducibility or release qualification.

## Guest entrypoint mode regression

Docker Desktop source mounts can make scripts executable even when Git records
them as `100644`. That can mask a cold Linux build's PID-1 boot failure. The
early feedback test checks the Git modes of directly executed guest entrypoints
(or actual executable access for a source archive), before compilation.

An optional differential ARMv5 regression uses the same pinned read-only
base/toolchain mounts and executable disposable `/tmp` described below:

```sh
sh /src/support/tests/test-qemu-md-v10-init-mode.sh \
    /base /toolchain/bin/go /src /toolchain/sbin/debugfs
```

It copies the base images into tmpfs, sets only the MD fixture init's inode
mode to `0644`, requires kernel `EACCES`/panic, then sets `0755` and requires
the full MD v1.0/Owner fixture to pass. The original rootfs hash must remain
unchanged. Temporary images/logs and guest processes are cleaned up. It
never attaches host devices or qualifies hardware. Normal CI needs no extra
negative boot: the fast source-mode contract and standard positive MD fixture
cover this regression's boundary.

## Current-source overlay lane

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
The combined internal M4.1 SMB/NFS candidate is also checked by the target
`testparm` and `exportfs` parsers. Its export is limited to a fixed loopback
rule on the disposable QEMU volume and is withdrawn immediately after the
parser/output check; no product config or service owner consumes it. The
Owner-backed candidates obtain storage from a fixed-roster M3.4 set
observation: every member Owner is locked in canonical order and revalidated
before an all-or-error snapshot is returned. The fixture roster contains one
synthetic volume; “complete” is scoped to that roster and is not proof of
complete physical storage discovery or EX4 compatibility. A separate
Owner-backed NFS-only candidate is also passed through the target `exportfs`
parser while its synthetic mount-owner tuple is live. That fixture writes only
one fixed guest export file, checks the loopback/read-only/all-squash/
anonymous-ID/fsid result and preservation of prior exports, removes the file,
reloads and requires the normalized export table to match its baseline. This
temporary parser round trip is distinct from product activation; no product
service owner consumes the candidate.

The same ARMv5 Owner fixture makes one direct `FileServiceSnapshot` call after
its existing disposable SMB enrollment/re-enable path. It checks that the
snapshot observes the one managed passdb entry only as redacted metadata,
reports both Owner accounts and local UID/GID reservations, and leaves the
captured native and Samba journals unchanged. The marker
`PHANTOWD_M41_OWNER_PASSDB_OBSERVATION_READY` is required by the smoke driver.
This assertion covers the observation call, not the surrounding fixture's
test-only account lifecycle; neither is product startup, an endpoint, or
service activation. The fixed QEMU backend is not a production passdb source.

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
auth files, not product credentials. The fixture-owned daemon remains running
through the subsequent disposable Owner identity/passdb observations, then its
process group is stopped and reaped before the NFS fixture unmounts the disk.
Cleanup removes only the created Unix accounts/group. No production
account/lifecycle API is added.

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

### M3.3-to-M3.4 mounted-storage evidence bridge

The full current-source ARMv5 smoke also carries the synthetic filesystem
identity from the read-only MD v1.2 mounted-array fixture through the
M3.4 mount Owner. The fixed QEMU-only Owner roster revalidates the live mount,
and its non-serializable evidence is adapted to a planner `StorageSnapshot`.
The check requires the expected filesystem UUID and device tuple, read-only
state, and no activation or HTTP surface; it emits
`PHANTOWD_M33_M34_PROVIDER_READY`. Run `support/test-api.ps1` for host checks
and ARMv5 cross-compilation, then the local ARMv5 QEMU overlay smoke for guest
execution. The recorded one-boot run passed; its separate two-boot persistence
fixture was skipped. This is a composed disposable-fixture test, not a
production M3.3 inventory-to-roster adapter, EX4 media qualification, or
service activation. The earlier run record mislabeled this fixture as MD v1.0;
source inspection confirms its `mdadm` arguments request metadata 1.2. See the
[version correction](../doc/sources/m33-m34-md-metadata-version-correction-2026-10-01.md)
and [immutable run record](../doc/sources/m33-m34-mounted-storage-provider-local-qemu-2026-10-01.md).

### MD v1.0 writer-to-host-parser fixture

On Windows, run `support/test-qemu-md-v10.ps1` for a focused check of the
offline MD v1.0 parser. It requires the already-present pinned Docker image,
Buildroot workspace/cache, QEMU base artifact, toolchain and util-linux source
archive; it uses `--pull never`, mounts the repository/base/cache read-only,
disables networking, and does not create persistent images or volumes. The
ephemeral container uses `/tmp` tmpfs for generated files and is removed on
exit. It rebuilds the API and host parser from current source into a temporary
copy of the base rootfs, and reuses the base volume-probe helper only after
checking that it advertises schema version 2. The current-source mdev rules
are overlaid into that temporary copy.

The guest uses a snapshot-backed root disk and exactly two writable 32 MiB
GPT disk images in tmpfs, attached with fixed synthetic SCSI identities. Each
image contains one synthetic Linux RAID GPT partition with distinct disk and
partition GUIDs. The bounded QEMU-only entry point asks ARMv5 `mdadm` to create
a two-member RAID1 with metadata 1.0 on `/dev/sdb1` and `/dev/sdc1`, verifies
partition geometry and array/member topology, then stops the array. The fixture
applies the fixed mdev device permissions and starts the same non-root,
`no_new_privs`, zero-capability broker service used by other QEMU checks. A
separate client running as the API UID sends only the fixed `observe-md-v1.0`
operation. The broker performs complete trusted discovery, GPT/sysfs
correlation, O_RDONLY generation-bound whole-disk opens and the firmware
`mdmetadata.InspectBlock` parser on selected RAID partitions; it rechecks
storage, mount and swap observations before returning. The API client receives
only redacted counts/status/limitations. The test requires two GPT disks, two
MD partitions, one metadata-consistent array and full active-role coverage.
No filesystem data is read, and the broker does not assemble or mount. There
is no HTTP endpoint for this operation. The block-reading provider exists only
in the `qemu && linux` test build; normal firmware returns unavailable without
opening disks. The guest then reboots. The host
independently invokes `phantowd-lab inspect-md-v1.0-partition` on each image, then
`inspect-storage-image-set` on both whole-disk images. The harness checks valid
GPT and MD checksums, distinct GPT identities, a shared redacted array
fingerprint, distinct member fingerprints, active roles 0/1, partition-1
correlation in the MD metadata comparison, unchanged member hashes,
and an unchanged base rootfs hash. The separate M3.4 stage formats only the
disposable MD array, reassembles it read-only, and verifies a read-only ext2
mount. The subsequent generic whole-disk scan is expected to return review
status because both RAID1 member images contain the same ext2 filesystem UUID
and both ext and MD signatures; its redacted JSON must show that one expected
duplicate while the MD metadata comparison remains consistent. The host never
formats, assembles or mounts. The two member files and reports are removed from
the private temp directory by the test trap. No NAS/physical disk or NAND/MTD
is read or written.

The GPT-partition-contained fixture, including the non-root broker operation,
passed locally on 2026-09-30 against the pinned Linux 6.18.54 QEMU artifact. On
2026-10-01 the focused wrapper passed again with an additional MD v1.0-to-M3.4
composition: after broker observation, the guest reassembled the synthetic
array read-only, mounted its ext2 filesystem read-only, revalidated the live
mount through the M3.4 Owner, and produced the planner snapshot. The host
component comparison passed; whole-image reconciliation returned the expected
review status for the shared ext UUID while MD metadata stayed consistent.
This run used the current working tree based on `develop` `74ca3f9` with
uncommitted changes, so it is not exact-head or hosted-CI evidence. It reused
the pinned Linux 6.18.54 base and verified inputs, not a new clean Buildroot/
SBOM build, and did not run the separate two-boot fixture. This synthetic
parser/provider/Owner test does not establish that real EX4 disks use this GPT
type/layout, nor does it establish EX4 hardware, WD metadata, migration,
recovery or compatibility qualification. The firmware provider remains
internal and is not wired to product startup or management HTTP. No real disk
or NAS was read.

To run the complete one-boot API/service smoke against the current source using
the same pinned image, cache volume and verified base artifact, use:

```powershell
.\support\test-qemu-md-v10.ps1 -StandardSmokeOnly
```

This mode runs `qemu-smoke.sh` (including the `processowner`-managed Samba
readiness/access/stop fixture, unexpected-exit, forced-stop and failed-start
cleanup cases) and skips only the separate two-boot state fixture. It passed
locally on 2026-10-02 against the working tree based on `e0dc29e` plus the
uncommitted M4.2 regression fix. One controlled BusyBox child exits
unexpectedly; another ignores `SIGTERM` during stop; a third ignores it while
readiness times out. The last case verifies that subsequent cleanup does not
erase `review-required` or permit restart. Every fixture requires the child
group to be gone. These children do not simulate an unexpected crash or forced
stop of `smbd` itself. The run verifies the existing pinned artifacts, does not
pull/build an image or create a Docker volume, and does not contact the NAS.
The default command remains the focused MD v1.0/M3.4 check described above.

## Evidence boundary

### Native service-launcher boundary fixture

Run `support/test-service-launcher.ps1` for the independent M4.4 launcher
prototype. It uses the already-present pinned image/toolchain and checks every
base artifact hash, copies the rootfs to tmpfs, builds two static ARMv5 programs
there and runs one networkless snapshot-mode guest. Only the private copy has
the helper/probe/init injected; the firmware artifact and its SBOM are unchanged.
Host refusal tests, static analysis and seven guest refused-launch cases precede
the positive namespace/root/credential/capability/FD/signal/PID/read-only proof.
Temporary root/share objects contain only generated markers. Original data
paths, sibling paths, `/proc`, `/dev` and an inherited host-root descriptor are
not visible to the child. The guest remains distinguishable from physical EX4
through its exact DT model and ARM architecture check.

The wrapper refuses missing existing caches, never pulls/builds an image or
creates a persistent volume, mounts inputs read-only, and removes its container
and tmpfs on exit. Full QEMU CI runs this same bounded fixture after producing
the baseline, retaining a synthetic failure log if it fails. It now also
compiles a QEMU-only Go fixture that invokes the real fixed-input IsolatedOwner
and checks readiness/stop/reap, argument/credential mutation, close gating and
pre-launch/live root-drift quarantine. Cold Go compilation exceeded the former
128 MiB fixture budget: full local/CI wrappers now use the same bounded 512 MiB
tmpfs, and the disposable compiler cache is removed before the rootfs copy.
This does not create a persistent volume.

It is not a product root constructor, process Set/ServiceRuntime integration,
live SMB/NFS test, clean image qualification or hardware evidence. Successful syscall-level
isolation alone does not prove a complete service authorization model.

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
identity scenario passed. Ten additional instrumented pairs and ten more local
repetitions on 2026-09-30 passed without reproducing it; the latter used the
manifest-verified cached rootfs (`7a45b86344ee36c60441efbe4adb6632dc76ce3baac610ad5b7e89b59fd06d6c`)
and current shell harness, not a clean source rebuild. Failure-only
process/descriptor probes and a parent-exit probe did not establish the cause.
Temporary probes were removed. This is non-reproduction, not a fix; the cause
remains unproven and unrelated to the identity-channel overload correction.
Cleanup labels state-volume,
Samba-data and copied-`/etc` unmount failures, and a host regression checks that
the state-persistence fixture releases its own descriptors. Neither lazy
unmounts nor automatic retries mask failures. Investigate any recurrence;
successful clean-reboot runs do not establish crash or shutdown robustness.

The QEMU-only failure path now emits `PHANTOWD_STATE_UNMOUNT_DIAG` before
returning the original unmount error. Its JSON is capped at 4096 bytes and
limits process records to the fixture owner and descendants. The `/proc`
enumerator reads at most 160 names plus one truncation sentinel, then caps
numeric PID records at 128. Normal PID-exit races are skipped; permission and
I/O failures remain visible as incomplete evidence. FD/cwd/root
references are reduced to fixed-anchor or synthetic-source categories, and
mount records expose only matching mount IDs and device numbers. Raw paths,
filenames, command lines, environments and unrelated processes are omitted.
Missing/capped observations are marked incomplete/truncated. This adds no retry
or alternate unmount behavior. Host fake-proc/bounded-scan tests, QEMU-tagged
`go vet`, a Linux-native `/proc` collection check and ARMv5 cross-compilation
pass. A current-source ARMv5 MD v1.0 overlay after the scanner refinement
passed, but did not execute this state-unmount path. A full two-boot state
overlay has not yet been rerun after the refinement; the historical EBUSY
remains unresolved rather than fixed.
See M0.2 in [the roadmap](../ROADMAP.md).

### Qualification limits

The standalone `support/test-service-launcher.ps1` lane also composes a single
fixed static child with `mountowner.IsolatedServiceRuntime`. It creates one
16 MiB ext2 fixture in bounded tmpfs and attaches it with a QEMU snapshot; the
manifest-verified base is read-only. Normal and substituted-source cases must
prove exact grant-only roots, denied original paths/read-only writes, root-pin
close exclusion, stop/reap before release and no restart from review. The guest
requires ordinary ext2 unmount success before completion. Its `/run` tmpfs is
explicitly mode0755: permissive default ancestors must not be worked around by
weakening the handoff's checks. Local builder1000 verification passed with the
same512 MiB budget used by the full local/CI wrapper. No image/named volume is
created; this lane neither installs the helper nor tests a real daemon profile.

This lane can exercise current userspace against the base's kernel and
packages without rebuilding Buildroot. It does **not** validate changed
kernel, Buildroot, package selections, libraries, complete overlay installation,
license packaging, SBOM regeneration or reproducibility. Files in the old
artifact's SBOM describe the base, not the injected copy. No generated image
from this lane may be published as a release or staged on an EX4.

Clean Buildroot/CI qualification is still required before merge/release. QEMU
does not qualify physical SATA, WD layouts, cooling, NAND or device recovery.
