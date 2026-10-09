# Fast API and file-service integration checks

## Bounded cached full validation

The existing QEMU and EX4 B2/B3 kernel-configuration auditors reject builtin
or module entries in the unused `CONFIG_CRYPTO_USER_API*` namespace (AF_ALG),
including future options. Internal kernel crypto libraries remain permitted.
No hash provider or kernel selection changes: cheap mutation tests plus
read-only resolved-config audits verify this build guard without compiling
another image. This follows [upstream AF_ALG guidance](https://www.kernel.org/doc/html/latest/crypto/userspace-if.html),
not a claim that the pinned kernel implements newer-version restrictions.

The QEMU builder selects one CPU job ceiling from Linux process affinity and
the visible cgroup v1/v2 quota hierarchy. Fractional CPU quotas round down, with
a minimum of one job. `PHANTOWD_BUILD_JOBS` can request a smaller positive
integer ceiling; it cannot increase concurrency beyond the observed limits.
Invalid values or unreadable/malformed quota data fail before compilation.
The selected budget reaches both GNU make's parallel build and Buildroot's
`PARALLEL_JOBS`, including Samba/WAF and early package builds. This avoids
using a host CPU count (for example 24) inside a four-CPU Docker quota. It is
not a memory/disk budget, measured speedup or fix for a Samba guest timeout.
The small `support/tests/test-build-jobs.py` regression executes the driver's
real parallel command boundaries without starting a compiler or QEMU.

The full driver qualifies the pinned Buildroot archive-helper cleanup with
`support/tests/test-buildroot-download-patch.sh`, then applies only its one-line
success-cleanup patch before package builds. Its direct regression executes
the real `mk_tar_gz` function: no empty marker survives, unrelated files remain,
content/exclusions/repeatability hold, and original/patched archives match.
Unknown helper/patch bytes and symlinked/missing inputs refuse. This is an
existing-source, small-tmpfs test; it does not remove historical package files,
change archive semantics, repair interrupted downloads or solve Samba timeouts.

The full builder first runs the same workflow path and exact fixed-count fuzz
roster contract as hosted host CI. Keep it synchronized when adding campaigns;
a stale declaration must fail before source authentication or compilation,
not consume a full build. This cheap gate does not replace the native/guest tests.

After the ordinary `support/build-qemu.ps1` has initialized the pinned image,
two fixed volumes, artifact permissions and output for the current defconfig:

```powershell
.\support\build-qemu.ps1 -CachedOnly
```

This runs the complete existing Buildroot/host/guest validation, not a reduced
test set. It inspects the local image and both named volumes before one
`--rm --pull never` container; it never calls image build/pull, volume create
or prune. Initialization markers, current config-keyed Go/target output and
builder write permissions are checked before compilation. Missing inputs
refuse without ownership repair, alternate output adoption or automatic retry.
Serialize use of these resources: inspection is not a lease against another
operator deleting a volume or changing an image tag. Do not run parallel builds
or change source during exact-source qualification.

The profile uses UID/GID1000, zero capabilities, no-new-privileges, 4 CPU quota,
6 GiB memory, 512 PIDs and a 1800-second outer timeout with 30-second kill grace.
`/tmp` is 2048 MiB, guest scratch512 MiB, API/toolkit Go caches768 MiB each;
all four are disposable tmpfs and do not accumulate in Docker's writable layer.
The cold complete API race suite reproduced linker space failure at256 MiB
and passed at2048 MiB. Full integration subsequently passed with that profile.
These are bounded allocations, not measured peak/minimum requirements or a
guarantee that future package/suite growth fits the same budgets.

The existing Buildroot workspace and bounded compiler cache remain writable:
cached mode does not prohibit normal dependency rebuilding/source downloads
or eliminate their persistent disk use. The ordinary40 GiB host-headroom check
still applies. No ports or physical devices are supplied; normal networking
remains for existing source/key verification. It does not emulate EX4 hardware,
authorize NAS writes, demonstrate clean reproduction or replace hosted checks.

`support/tests/test-cached-qemu-wrapper.ps1` mocks only the command boundary
and checks profile/refusal/no-retry behavior. The Linux Python preflight test
executes the actual embedded shell against disposable initialized/missing/
changed-config/nonwritable fixtures. Neither is itself a full build result.

## Actual libatomic dispatch on ARM926

`support/test-atomic-dispatch.ps1` reuses the existing pinned image, toolchain
and manifest-checked base. It creates no image or volume, mounts inputs
read-only, caps CPU/memory/PIDs and uses only 256 MiB disposable tmpfs. One
90-second QEMU ARM926 boot has no network, forwarded ports or host devices;
only a copied rootfs snapshot is attached. Original base hashes must match.

The temporary C probe drops to UID/GID 1000 with no groups/capabilities and
`no_new_privs` before opening the image's exact `libatomic.so.1.2.0`. The host
first compares that file's SHA-256 with the existing target library. Versioned
`dlvsym` calls force 36 real library function resolutions rather than inlined
compiler builtins. Resolved offsets must differ from the IFUNC resolver
offsets in GNU readelf's dynamic symbol table. This demonstrates dispatch,
not identification of every selected implementation or symbol/ISA safety.

Four widths (1/2/4/8 bytes) each exercise 50 sequential semantic scenarios,
including valid memory-order variants, CAS success/failure, upper-64-bit
differences and unsigned wraparound; two threads add 4,000 increments per
width on the single-CPU guest, with neighbouring-cell guards checked. The
kernel kuser helper version is observed (at least 5 required). A separate
missing-symbol run must fail without emitting readiness. A bounded host
comparator rejects incomplete/duplicate/reordered/contradictory evidence.

The full build runs this same fixture after producing its exact artifacts;
cheap refusal tests run before compilation. QEMU-only changes are excluded
from EX4 B3 compilation. A local cached guest pass is not a full new image
build, hosted result, exhaustive memory-model/SMP proof, physical EX4 test or
product service activation. An aggregate ARMv7/Thumb-2 attribute on this mixed
library is neither sufficient acceptance nor sufficient rejection.

## Retained static-code Owner

`support/test-runtime-owner.ps1` uses the existing pinned image/workspace and
hash-verified QEMU base, with read-only mounts and no network/host-device
attachment. It never builds/pulls an image or creates a volume. Its rootfs copy,
compiler cache and guest data are disposable; the compile cache is removed
before the image copy to fit the 512 MiB tmpfs budget.

The separate guest has a finite 120-second budget, no retries and no Samba
entropy/network readiness dependency. A copied static fixture checks code/root
pin lifetime, caller close, immutable launch inputs, duplicate-start refusal,
stop/reap before release, same-byte inode replacement before launch, live root
drift and permanent review after restoration. A child that ignores SIGTERM
also proves that forced cleanup keeps code pins: normal unmount returns the
expected kernel `EBUSY` before explicit reap verification, then succeeds after
release without clearing review. This deliberate code-pin check is not the
unresolved intermittent state-volume unmount issue below. Original base hashes must remain
unchanged. This tests no product HTTP/service activation, dynamic Samba profile,
NFS export authority, physical disk or EX4 hardware.

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
Host refusal tests, static analysis and eleven guest refused-launch cases precede
the positive namespace/root/credential/capability/FD/signal/PID/read-only proof.
Temporary root/share objects contain only generated markers. Original data
paths, sibling paths, `/proc`, `/dev` and inherited host-root descriptors,
including FD 511, are
not visible to the child. The guest remains distinguishable from physical EX4
through its exact DT model and ARM architecture check.

Both diagnostic descriptors must be writable anonymous pipe ends; named
filesystem FIFOs and read-only pipe ends are rejected. The successful static
probe must actually write and flush its readiness line. Invalid stderr cases
still require refusal exit status and absence of probe readiness, even when
the rejected descriptor cannot carry an error line.

The wrapper caps four CPUs, 2 GiB memory and 512 PIDs. It refuses missing
existing caches, never pulls/builds an image or
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
On 2026-10-03, a deterministic native subprocess regression exposed a separate
cleanup defect: direct-parent exit could report success while an adopted
same-group child retained a directory descriptor. The reboot Samba fixture
now requires both parent reaping and process-group absence, with bounded TERM
and KILL phases; forced cleanup still fails. Linux tagged vet/race, Windows
preflight/cross-compilation and the actual ARMv5 smoke/two-boot overlay pass.
That proves the lifecycle correction, not causality or resolution of the
historical `EBUSY`. No unmount delay/retry, lazy unmount or product runtime
privilege change is introduced; group-escaping descendants are not contained.
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

`support/test-smart-report.ps1` runs the internal SMART parser and generation-
bound coordinator tests in the **same ARMv5 boot**, using synthetic JSON and
fake backends. Each binary needs its own exact success marker. It reuses the pinned image/workspace
read-only, compiles in bounded tmpfs, verifies the base hashes and injects the
test binaries into a disposable snapshot; no SMART executable, additional data
disk, network or physical device is supplied. No new image/volume is created.
The full integration wrapper runs the same fixture against its just-built base.
The focused container is non-root, capability-free and network-free, with two
CPUs, 2 GiB memory, 128 PIDs and disposable RAM caches/scratch. The default base
directory is resolved inside the script body for Windows PowerShell compatibility;
command-boundary mocks test default/explicit input and dependency/run refusals.
Runner mocks separately test missing-marker refusal, one fake boot, scratch
cleanup and unchanged inputs; they are not guest execution. Exact path contracts
select host/QEMU validation for fixture changes, not an unrelated EX4 B3 rebuild.
This qualifies report interpretation and fake-backend coordinator semantics
only, not authenticated smartctl/device provenance, real subprocess cleanup,
physical transport/standby policy, collection, history, jobs or disk health.

The separate [CPU-only producer oracle](SMART-REPLAY.md) runs real upstream
smartctl 7.4 or 7.5 with its generic (no hardware) backend and invented stdin ATA
responses. Each selected version checks seven actual native reports against the same Go parser,
including exit-zero SMART-disabled and partial failing status. It creates no
image/volume and does not replace ARM execution or any physical collector gate.
The new C++-enabled defconfig requires a complete toolchain rebuild. The separate
`support/test-smart-replay-arm.ps1` lane then executes a statically linked
generic-only smartctl 7.5 and the same seven invented-input projections inside
ARMv5 QEMU. Missing C++ fails before guest launch. The complete local rebuilt
image and existing guest/service suites passed on `dd55481`, including this
actual producer and independent final artifact hash verification. This cached
run is not hosted feature or independent clean-build qualification; do not
count the pure-parser or native lanes as an ARM producer pass.
See [the producer contract](SMART-REPLAY.md).

The same producer boot now additionally executes the fixed single-use capture
Owner and SMART coordinator through a test-only `smartcapture` adapter. Seven
actual generic reports retain their genuine exits/assessment, while fake source
replacement discards the report and restoration cannot clear review. A second
exact success marker is mandatory. Inputs are regular synthetic stdin files,
not devices, and source provenance remains fake. Guest test debug symbols are
omitted to fit the existing snapshot; injected bytes are independently checked
before boot rather than trusting debugfs status. No new image, volume, boot stage,
hardware backend or product authority is added.

`support/test-samba-root.ps1` additionally tests actual multi-user Samba inside
a restricted read-only root/private mount namespace, using only fixture state
and explicit subdirectory grants. UID 0 retains six bounded capabilities for
Unix client impersonation, not the generic launcher's non-root profile.
Ownership, wrong-password/access denials, Unix-mode enforcement, kernel RO,
original-path/symlink denial, one Unicode filename and owned-group stop are
checked. This is a distinct test-only native fixture, never installed into the
product image. See [runtime profile and remaining gates](SAMBA-RUNTIME-PROFILE.md).
The current wrapper compiles once and runs fresh service/native/candidate/
lifecycle/fault/data
snapshots, each bounded to 180 seconds. It independently verifies each phase,
requires all six complete proofs with matching runtime census, then prints combined
coverage. This is not a state/daemon lease across boots. Every original contract,
base check, worker admission fence and deadline remains required by the complete
suite. The lifecycle guest independently creates real disabled-first accounts
and explicitly enables them, then tests retained startup/supervision and coordinator
revocation. Candidate and state-alias fault now have independently enrolled
guests instead of accumulating inside lifecycle. Candidate retains the SAME
Owner/backend/runtime/roster; fault closes enrollment admission before its NEW
service consumer and disposal subprocess. Lifecycle does not duplicate native's first
daemon/idle-disable cycle. Authentication, idle/live disable and backend-binding
proofs remain mandatory in the native guest, never fabricated in lifecycle.
Independent inspector refusals and generic-adapter retention experiments now
run once, in service, and remain mandatory in the complete union. Native and
candidate/lifecycle/fault/data each run the SAME zero-capability/read-only boundary and actual
complete census/hash inspection of their OWN staged tree, but emit a separate
`CENSUS_READY` proof explicitly saying those independent controls did not run.
The new data guest independently creates and enrolls its own real identities,
then verifies fixed SMB transfers and denials through the SAME retained planned
service. Startup/preparation and the new data action retain separate 40/20-second
budgets. No earlier guest supplies identity, passdb, runtime or mount authority.
There is no borrowed authority, cached hash or weaker worker revalidation.
Worker/readiness/stop/guest deadlines remain unchanged. Candidate's distinct
declaration and prepared-input scenarios use two serial30-second contexts
instead of sharing30; failed/expired first work cannot proceed or retry and
parent cancellation remains binding. This is fixture orchestration, not a
product timeout extension. The host verifier rejects missing
original service proofs, incomplete census, wrong-phase/duplicate markers and
false claims that omitted controls ran. A local all-six pass is not proof
that intermittent hosted enrollment/guest timeouts are fixed.
Deliberately quarantined captures and identity references remain held until a
disposable subprocess proves group stop and exits; that exit is not recovery.

For a focused local diagnosis, select exactly one unchanged guest campaign:

```powershell
.\support\test-samba-root.ps1 -Campaign lifecycle
```

Allowed selections are `service`, `native`, `candidate`, `lifecycle`, `fault`,
`data`, `exit`, `held` and default `all`.
Invalid values fail before guest/fixture construction. A focused run still
compiles current source, checks all base hashes, uses read-only inputs and
bounded tmpfs, verifies that phase's exact proof, retains its 180-second limit
and cleans its disposable container. Its completion explicitly reports
`complete_image=false`; it cannot substitute for the default eight-campaign
qualification or clean Buildroot/hosted/release evidence. Existing full-build
callers continue to select all campaigns without modification.

The separately enrolled `held` guest adds normal cancellation/full runtime
Close for the planned service's SAME fixed authorized IPC$ holder. All seven
older proofs remain mandatory and unchanged; no old idle observer is relabeled
to cover the extra group. Complete mode requires all eight ordered logs and
equal runtime census, with one overlay compilation and independent snapshots.
This does not qualify open data handles, in-flight loss or durable reconnect.

For troubleshooting, add `-DiagnosticLogs` to the same command. After each
guest exits, this opt-in mode emits its complete bounded log as one escaped JSON
record (`phantowd-qemu-campaign-diagnostic`, schema 1, `qualifying=false`) with
the campaign and actual exit status, including on timeout. Newlines and control
characters stay escaped; a record is never a proof marker. The default emits no
such records. This preserves useful successful diagnostic logs before tmpfs
cleanup without writing persistent log files, adding a container/volume, altering
the guest, retrying or changing acceptance and deadlines. These are synthetic
fixture logs only, not a product/device log collector; save the command output
if needed. Additional temporary instrumentation still requires a separate clean
replay after it is removed.

The QEMU-only native, candidate, lifecycle, fault and data fixtures also emit bounded cumulative
`PHANTOWD_DIAG_NATIVE_PHASE` timings with fixed phase names, `qualifying=false`
and `scope=qemu-only`. The monotonic clock starts inside credential setup,
not at host compilation or guest boot. Timings distinguish enrollment, backend
observation, authentication, revocation, verified authority closure and the
later new data profile. Candidate/startup/fault timings belong to their own
independently enrolled traces, never a continuous authority across boots.
A last timing row only bounds completed work: it neither identifies a blocked
worker inside the next phase nor proves its success. All original proof markers,
descriptor census, hashes and command/phase/180-second guest limits remain
independent and mandatory. Passing telemetry tests is not a timeout fix.

### Diagnose a native fixture timeout before a full CI build

Use the existing matching pinned image, workspace and manifest-verified base:

```powershell
.\support\test-samba-root.ps1 -Campaign lifecycle -DiagnosticLogs
```

Do not edit source or run another build against the same workspace while it
executes. Preserve the exact Git revision, uncommitted changes, base manifest,
command, actual terminal status and complete escaped diagnostic record. This
lane neither downloads a new image nor creates a named volume; its scratch is
disposable. It still requires matching cached dependencies and checks the
selected campaign, not an entire new firmware image.

Read the **first failed operation** rather than treating every elapsed timer
as the same timeout:

| Boundary | Current fixture scope | What a failure does not establish |
| --- | --- | --- |
| Initial native credential setup, 60 s | Construction and explicit enrollment of the fixture accounts; precedes `phase=enrolled` | The later coordinator operation was reached |
| Lifecycle preparation, 20 s | Original journal admission, canceled-disable refusal and creation/qualification of two held clients | Revocation or continuity has completed |
| Lifecycle revocation, 45 s | Stale-revision refusal, actual disable, successor journal and original peer/new-login verification | Every individual worker exceeded its own deadline |
| Guest, 180 s | The complete disposable boot and selected campaign | A specific account, worker or coordinator caused expiry |

These are test-context limits, not physical EX4 performance guarantees or
product request deadlines. See the actual [credential fixture](../src/phantowd-api/cmd/qemu-runtime-bundle/native_credentials_linux.go)
and [lifecycle fixture](../src/phantowd-api/cmd/qemu-runtime-bundle/native_identity_startup_linux.go)
when changing their orchestration. A cumulative parent deadline can expire
after several individually successful operations; a child deadline can also
expire while its parent still has time. Neither permits ignoring uncertainty,
reusing reviewed authority or skipping a verification.

The current QEMU-only lifecycle driver replaces its former cumulative45 context
with serial preparation20 and revocation45 contexts. This deliberately raises
the combined contextual allowance to65 seconds; it is not a performance gain
or product request policy. The SAME service, Owner, startup-fixed backend,
journal and opaque original session pair cross the handoff. Uncertain/expired
preparation refuses the second phase, shorter parent deadlines still bound both,
and a late nil return cannot report success. Contexts are cooperative, not a
guarantee to preempt an uninterruptible callback. Worker/readiness/stop and the
external guest180 guard are unchanged. Fake-clock regression tests exercise the
actual internal phase runner without inventing runtime/session authority.

A focused local ARMv5 lifecycle replay passes all original proofs after this
change. An unchanged-source fresh guest also passed, while another failed on an
independent post-admission worker deadline during client preparation. Therefore
one candidate pass does not establish that historical hosted outer deadlines
or independent child expiries are fixed. Full current-source integration and
own-head hosted qualification remain required; do not rerun heavy CI merely to
substitute a lucky green for a diagnosed failure.

Fixed `PHANTOWD_QEMU_NATIVE_WORKER_FAILURE` phase/reason labels are diagnostic,
not authorization. `reason=other` is not proof that no deadline occurred:
an intermediate refusal can discard the underlying typed cause. Conversely,
absence of a worker label does not mean the campaign succeeded. The last
`PHANTOWD_DIAG_NATIVE_PHASE` row identifies completed work only; missing
`phase=enrolled` means a proposed *post-enrollment* experiment did not reach
its trigger, not that its intended setting was applied.

The planned source/exit subprocess boundary also emits fixed-label
`PHANTOWD_QEMU_PLANNED_FAULT_SUBPROCESS_FAILURE` diagnostics on failure. Its
`deadline` flag describes the outer 90-second child context, `child_failed`
describes the command result, and `proof_match` describes exact captured-proof
equality. Validated, deduplicated `PHANTOWD_QEMU_PLANNED_FAULT_FAILURE` rows
identify fixture phases and typed deadline/review membership without relaying
raw child errors, commands, paths, credentials or passdb. An absent child row
does not localize the cause; `deadline=false` does not rule out an inner expiry
whose typed error was redacted earlier. Unknown/malformed rows are discarded.
All rows are `scope=diagnostic-only`; even diagnostics accompanied by the
expected proof still fail exact child-proof equality. The 1-KiB child-output
bound, original proof bytes, deadlines and verifier remain unchanged. This
observability improvement does not resolve the intermittent all-campaign fault
failure or qualify product/hardware operation.

Require the original verifier's terminal success and complete selected-phase
proofs. A failed fixture may deliberately shut down with guest exit 0; that
does not override failure markers or the host verifier's nonzero result.
Save complete JSON diagnostics before cleanup: a clipped console tail is not
the full trace. A new disposable diagnostic guest is not recovery or a retry
of a reviewed Owner. Local success, changed CPU quotas, or narrower diagnosis
cannot waive exact-head hosted checks, clean-build or hardware qualification.

Its fixed runtime now includes IBM850 plus a strictly bounded, hash-verified
conversion catalog. A dynamic probe tests exact non-ASCII CP850/UTF-8 conversions
and refusals inside the restricted root; the fixture rejects ASCII fallback.
Use a matching new-config target/base after rebuilding. An old cache without
the converter is expected to fail, not silently borrow host/staging converters.

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

The declared-share pin campaign also requires
`PHANTOWD_DECLARED_SHARE_CLOSE_READY`: healthy actual mounted admission followed
by a real premature original `os.File` close must retain review, the later
input, original grant clones and full roster. Repeated operations cannot issue
copies, admit replacements or settle the handoff. Independent never-launched
fixture disposal checks original clone identities and leaves the lifetime in
review; final FD equality and ordinary source unmount remain required. This
is controlled premature-close characterization, not kernel EIO, live Samba
teardown or a production recovery procedure. The original guest deadline and
all other markers remain unchanged.

This lane can exercise current userspace against the base's kernel and
packages without rebuilding Buildroot. It does **not** validate changed
kernel, Buildroot, package selections, libraries, complete overlay installation,
license packaging, SBOM regeneration or reproducibility. Files in the old
artifact's SBOM describe the base, not the injected copy. No generated image
from this lane may be published as a release or staged on an EX4.

Clean Buildroot/CI qualification is still required before merge/release. QEMU
does not qualify physical SATA, WD layouts, cooling, NAND or device recovery.

### Avoid rebuilding compiler-cache prerequisites

The pinned build container includes CMake from the authenticated Debian
snapshot. Buildroot still selects it through its own host-tool suitability
check; the project does not override CMake or remove dependencies manually.
Before host-Go bootstrap, `test-buildroot-system-cmake.sh` uses a fresh
disposable configuration to check the real minimum and dependency graph.
An unsupported or missing system tool fails early instead of unexpectedly
rebuilding host-cmake, which cannot benefit from ccache itself. The source-only
preparation lane does not run this QEMU-specific probe.

After pulling a build-environment change, run the ordinary
`support/build-qemu.ps1` wrapper once before `-CachedOnly`. It refreshes the
fixed image tag while reusing the same two project volumes; cached-only mode
never rebuilds an outdated image automatically.

This changes the host environment, not the target configuration or validation
ladder. Measure hosted timings rather than assuming a cache hit implies a
fast build. Keep clean builds separate from reused local outputs.
