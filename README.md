<p align="center">
  <img src=".github/assets/phantowd-ex4-banner.png" alt="PhantoWD EX4: a four-bay NAS with orange ghost branding" width="700">
</p>

# 👻 PhantoWD EX4

A community replacement firmware project for the **WD My Cloud EX4**:
a maintained, local-first NAS with a web management interface, modern file
sharing, recoverable updates, and a conservative migration path for existing
disks.

[![QEMU integration build](https://github.com/PhantoNull/phantowd-ex4/actions/workflows/qemu-armv5.yml/badge.svg?branch=develop)](https://github.com/PhantoNull/phantowd-ex4/actions/workflows/qemu-armv5.yml?query=branch%3Adevelop)
[Roadmap](ROADMAP.md) · [Implementation status](IMPLEMENTATION-STATUS.md) · [Contributing](CONTRIBUTING.md) ·
[Builds](https://github.com/PhantoNull/phantowd-ex4/actions/workflows/qemu-armv5.yml) ·
[Releases](https://github.com/PhantoNull/phantowd-ex4/releases)

## Can I install it?

**Not yet. There is no installable PhantoWD firmware release or supported
upgrade procedure.** CI artifacts are development/test outputs, not WD
dashboard updates. Do not flash them, replace NAND partitions, or attach
valuable disks to an experimental image.

No legacy disk layout is currently product-qualified for migration; see the
[storage compatibility matrix](STORAGE-COMPATIBILITY.md).

You can develop and test the software in QEMU without connecting a NAS.
Physical EX4 work is still restricted to separately reviewed research tests.
A public installer will require qualified board support, storage compatibility,
signed updates, and demonstrated recovery.

## What works today?

These capabilities describe this source revision; they are not a claim of a
production-ready appliance.

| Area | Available now | Not yet qualified |
| --- | --- | --- |
| Build | Pinned Buildroot 2025.02.18 LTS / Linux 6.18.54 LTS; ARMv5 QEMU image, package SBOM and automated tests | Installable EX4 image and release qualification |
| Web interface | Diagnostics, development administrator authentication/password changes, SMB/NFS policy previews (including same-volume configured-path overlap warnings) and opt-in policy editing | Product setup/recovery, certificate lifecycle and live service administration |
| File services | Isolated SMB3/NFS fixtures; M2.4 Owner-bound disabled-first account lifecycle and M2.5 session revocation pass ARMv5 QEMU. The one-boot ARMv5 QEMU smoke runs `processowner` around disposable `smbd`, waits for a real SMB readiness request, verifies access policy and stops the owned process group. Controlled BusyBox children also test unexpected exit and ignored-`SIGTERM` forced-stop escalation: both enter `review-required`, block restart and leave no process group behind. These synthetic children do not simulate an unexpected `smbd` crash. M4.1 compiles non-serializable combined SMB/NFS candidates; freshness binds Owner identity evidence and the canonical complete storage tuple. `BuildFromOwners` constructs an NFS-only candidate while holding the fixed-roster mount Owners first and identity Owner second; only in-memory planning runs under both locks. ARMv5 QEMU uses one synthetic volume, rejects stale identity/storage fingerprints and performs no Samba enrollment. Target `exportfs` separately accepts and withdraws an Owner-backed candidate in the disposable guest, restoring its prior export table. The synthetic combined candidate's `testparm`/`exportfs` parser checks remain separate fixtures; none uses a trusted production storage provider or activates a product service. | Trusted complete production storage snapshot provider/adapter, complete legacy identity inventory/import, persistent product Owner/service startup, transactional service activation and recovery, HTTP authorization/UI and account lifecycle; in-flight SMB handles/durable reconnects and production data-preservation semantics remain unqualified |
| Storage | Read-only schema-v2 metadata and complete-inventory discovery; separate non-root broker with read-only device rules, `no_new_privs` and zero capabilities. PR #44's mounted filesystem UUID / MD correlation passed exact-head host, Stage B3 and ARMv5 QEMU checks and merged as `db9fd33`. Local M3.2a/b/c/d adds private GPT correlation and duplicate classification, generic declaration hints, plus a dashboard-triggered, authenticated manual `POST /api/v1/storage/gpt-observation`; page load and ordinary refresh never scan GPT metadata. The local ARMv5 QEMU smoke exercises this POST through the real broker on two distinct read-only synthetic GPT clones, verifies duplicate GUID/PARTUUID classification, and checks aggregate-only redaction. Full local Buildroot/package integration, QEMU smoke and the state-reboot fixture passed on `1358202`; artifact SHA-256 checks passed. The run reused the fixed Buildroot/cache volumes and does not establish independent clean-build reproducibility. MBR remains unsupported; errors return no partial result. No mount/import/repair/write action is authorized. M3.3's trusted MD v1.0 provider remains internal, has no manual real-disk endpoint, and passes the disposable ARMv5 QEMU fixture. The M3.4 internal mount-owner pins source/target descriptors, revalidates and exposes a non-serializable per-volume observation under its lock, and passes QEMU path-replacement regressions; it is not a complete collector, product service wiring or EX4 qualification. The host-only image research tool reads and compares generic MD metadata, not an EX4-qualified layout. The mountguard closes its pinned Root after failed identity/state checks; this does not itself revoke returned descriptors or dependent services. Desired SMB/NFS policy uses distinct logical `VolumeID` and expected `FilesystemUUID` types, but no persistent resolver exists. | Hosted CI and EX4 qualification remain pending; host/QEMU fixtures are not hardware qualification. Content reads, mount/import, global-use accounting, persistent identity, supported WD import and product RAID management remain unqualified or unimplemented |
| EX4 hardware | One bounded Stage B3 Linux 6.18.53 RAM trial with both HDDs removed: both ports briefly reached 1 Gbit/s/full duplex; `eth1` retained a placeholder MAC; five internal sensor readings were observational only. See [board notes](board/wd/ex4/README.md#stage-b3-combined-network-and-sensor-observation). | Sustained dual-port networking, factory MAC2 handoff, independent thermal safety, cooling/controller, storage and recovery |

M4.2's one-boot QEMU smoke also verifies that a forced cleanup during a failed
service start cannot be cleared by calling `Stop` again: cleanup is verification
only, `review-required` persists and restart remains blocked. This is a
synthetic child-process regression, not product service activation or a real
`smbd` crash test.

An internal Linux `processowner.Set` now sequences a fixed set of child
processes: every member must pass readiness, a later startup failure rolls back
earlier members in reverse order, and the aggregate generation advances only
when the whole set is ready. If one member exits unexpectedly, the set blocks
restart but leaves healthy peers running until explicit `Stop`; cleanup does
not clear review. Local ARMv5 QEMU exercises these transitions with disposable
BusyBox children. This is not yet an SMB/NFS service manager, configuration
transaction, persistent owner or product activation path.

The local M2.4 Owner implementation now has an in-process, read-only
`identityowner.SMB(id).Review` for an already quarantined `review-required`
operation. It verifies the current Unix identity and returns only redacted
Samba metadata; it cannot clear quarantine, mutate Samba, or be invoked through
RPC/HTTP. Local Linux API tests and ARMv5 test cross-compilation pass; this is
not product operator recovery or EX4 qualification.

M3.3 keeps the trusted MD v1.0 reader connected to discovery only through an
internal provider exercised on disposable QEMU media; there is no manual
endpoint that scans real disks. The M3.4 mount-owner is likewise an internal
prototype, not connected to the broker or product startup.
Its fixed-roster collector now locks and revalidates every declared Owner
before returning an all-or-error snapshot; the M4.1 planner fixture contains
one synthetic volume, so “complete” does not mean complete appliance
discovery. A separate M3.5 ARMv5 QEMU fixture uses two distinct synthetic
filesystems and verifies that loss of one quarantines only that Owner and
revokes its tracked handles, while the healthy volume remains usable. The old
anchor's return does not revive the lost Owner, and reacquiring the complete
roster remains all-or-error.
An internal roster lease now acquires every member under the same canonical
lock order or returns no lease, rolls back partial acquisition on revalidation
failure, routes directory opens by logical volume ID, and closes tracked
descriptors on group release. Host tests cover two-member drain exclusion and
failed-acquisition rollback. The one-boot local ARMv5 QEMU smoke exercises the
group lease and two-volume loss path on disposable ext2/MD-backed media; a
separate healthy Owner can still issue a fresh direct lease after the peer is
quarantined. This is fixture behavior only, not product service isolation or
volume-loss monitoring.
Its QEMU-only driver uses the pinned source and target descriptors with the
Linux `open_tree`/`move_mount` API; if that API fails, it does not fall back to
a path-based mount. Host tests and a current-source ARMv5 QEMU overlay cover
lease gating, identity-change revocation, ambiguous mount/unmount outcomes,
and injected source/target path replacements. A late target replacement is
never used as the mount destination: the descriptor-pinned original object is
used, then the Owner enters `review-required` without a lease. Source
substitution is likewise quarantined before lease issuance. Current-source
Windows API tests, Linux API tests and the local ARMv5 one-boot QEMU overlay
pass. The QEMU run reused read-only cached inputs and temporary overlay space;
it was not a clean Buildroot build, two-boot persistence run, or hosted CI run.
No real EX4 media was touched, and this does not qualify physical EX4 behavior.

The current-source M4.4 QEMU-only `ServiceHandoff` accepts fixed internal
`ServiceShare` roots and clones only those declared subdirectories from pinned
`O_PATH` descriptors into a volatile handoff. It rejects whole-volume `.`,
invalid or overlapping roots, pins the source roster, and applies
`nosuid,nodev,noexec` plus read-only mount attributes when requested. ARMv5
QEMU proves the consumer can read a synthetic file inside the share, cannot
see a sibling outside the cloned subtree, and gets `EROFS` when writing through
a read-only binding. The handoff still validates clone identity, and
`ServiceRuntime` stops its fixed process set before teardown on source loss;
uncertain stops retain the lease without retry.

This is only a share-scoped pathname view, not yet an authorization boundary:
services still share the host mount namespace, so the original volume path may
remain reachable and could bypass the read-only clone if Unix permissions
allow. All shares in one handoff are visible to its fixed service group. There
is no per-service grant/ACL enforcement, private service mount namespace,
production storage constructor, or daemon wiring. Do not enable this prototype
on user data. Local Windows/Linux API tests, ARMv5 cross-compilation and the
one-boot ARMv5 QEMU smoke pass with existing read-only Buildroot inputs and
temporary overlay space; clean-build, two-boot, hosted exact-head and EX4
qualification remain separate. No NAS, physical disk, NAND/MTD, flash, or user
data was accessed.

A separate single-static-child `IsolatedServiceRuntime` now joins a dedicated
grant-only handoff to the pinned native launcher. Its ARMv5 QEMU fixture proves
original volume paths are unreachable, read-only writes are denied, direct
teardown is blocked while the child runs, and normal/source-loss cleanup reaps
the child before releasing grants. This does not change the ordinary process
set's limitation above, install the helper into product startup or qualify
Samba/NFS daemon profiles. See the
[mount-owner contract](src/phantowd-api/internal/mountowner/README.md).

A focused local ARMv5 QEMU check now compares mdadm-authored MD v1.0 metadata
created on partition 1 of two synthetic GPT disk images, each backed by a
temporary 32 MiB tmpfs file. In the guest, the firmware's bounded MD reader
checks each partition through generation-bound, read-only descriptors; the
firmware component correlator also requires matching array fields and event
counters, component data sizes, unique member identities/roles, and complete
active-role coverage.
The host independently validates each selected partition and reconciles both
whole-disk images. It also extracts the two exact GPT partition ranges to
temporary regular files and runs `inspect-md-v1.0-component-set`; checksum,
array identity, distinct members, complete active roles and unchanged source
hashes are required. An internal firmware
coordinator also performs complete trusted discovery, GPT correlation,
RAID-partition-only reads and storage/mount/swap rechecks. It is exercised only
by this disposable QEMU self-test, not by the broker protocol or an HTTP
endpoint. The broker probe does not read filesystem data or assemble/mount an
array. A separate M3.4 fixture stage formats only the disposable array, then
reassembles it and mounts ext2 read-only to verify Owner evidence and a planner
snapshot; no user file content is read. This is not EX4 compatibility or
hardware qualification; see the
[fast test instructions](support/QEMU-FAST-TESTS.md).

Read-only storage discovery now refuses the entire assessment before opening
candidate disks if a nonzero mount device number cannot be mapped to the
complete sysfs block inventory. This is still a point-in-time, current-namespace
check, not proof of global storage-use exclusivity or EX4 qualification.

After the bounded state-unmount diagnostic refinement, a current-source API/
volume-probe overlay on `develop` `aedd22e` passed the full ARMv5 QEMU smoke and
the complete two-boot state-reboot fixture. Both state-volume unmounts succeeded
and the diagnostic did not fire; the historical `EBUSY` remains unexplained,
not fixed. This used an existing manifest-verified base and is overlay evidence,
not a clean Buildroot rebuild, hosted CI, or EX4 qualification.

The host-only `phantowd-lab inspect-storage-image-set` tool now correlates
bounded GPT, ext and Linux MD v1.2, v1.0 and 0.90 metadata across supplied
whole-disk image files, redacts identities, and withholds cross-image
conclusions when a GPT input is invalid. Its results are generic evidence only:
WD compatibility stays unqualified and migration, assembly and mounting are
never authorized.

The focused local M3.3/M3.4 MD v1.0 fixture now passes on the working tree
based on `develop` `74ca3f9`: its non-root broker observation is followed by
disposable read-only reassembly/mount and an M3.4 Owner-backed planner snapshot.
The host reports the expected duplicate ext UUID across RAID1 members as
review while confirming MD metadata consistency. This was not an exact-head or
hosted-CI run; the tested changes were still uncommitted.

The API and dashboard remain development-only and guest-loopback-only by
default. Do not expose them through a LAN listener or reverse proxy.
[Component contracts](src/phantowd-api/README.md) explain the precise boundaries.

An independent [native service-launcher prototype](src/phantowd-service-launcher/README.md)
now passes local ARMv5 QEMU tests with a restricted root, private mount namespace,
non-root credentials, zero capabilities, inherited-FD/signal cleanup and preserved
PID/process-group ownership. Seven invalid-launch cases are refused. The internal
`IsolatedOwner` now pins its fixed inputs and supervises a static synthetic child;
input drift stops/quarantines it and restoration never clears review. The
separate single-static-child handoff composition described above is tested;
trusted daemon-root construction, isolated multi-process Set integration, Samba
privilege profiles, kernel NFS control and product init remain missing. The
host-only research toolkit can derive a restricted ELF dependency candidate;
this is not a trusted runtime manifest. No live product service is enabled.

A separate local ARMv5 loader differential now confirms the cached Samba
candidate's hashes, aliases and 104 dependencies (105 ELFs including smbd), without
starting the daemon or changing the original image. Daemon-root/state/privilege
qualification remains open; see the [fast test instructions](support/QEMU-FAST-TESTS.md#fixed-samba-elf-loader-differential).

A separate disposable ARMv5 Samba fixture now exercises a restricted root,
private mount namespace and bounded root capabilities while preserving distinct
Unix users. Real SMB3 clients verify ownership, access denials, read-only grants,
denied original paths and one Unicode filename roundtrip. It is not an installed
helper, trusted product manifest or live-service activation; see the
[profile and remaining qualification gates](support/SAMBA-RUNTIME-PROFILE.md).
The complete local incremental pipeline passed on feature commit `fba213d`,
including these checks, native isolation and the two-boot state fixture. This
is not an independent clean build, hosted feature result or EX4 qualification;
[implementation status](IMPLEMENTATION-STATUS.md) separates them.

The badge tracks the `develop` integration branch, not every feature branch.
For build evidence, open the relevant workflow run and check its **commit,
conclusion and artifacts**. A previous green run does not validate a newer
commit; QEMU success does not prove EX4 hardware safety. Source pins are
authoritative in [versions.env](versions.env).

## Roadmap

The detailed [implementation roadmap](ROADMAP.md) defines task IDs, dependencies,
acceptance tests, safety constraints and contributor handoffs.

| Milestone | State | Outcome |
| --- | --- | --- |
| [M0: Engineering baseline](ROADMAP.md#m0-engineering-baseline-and-test-reliability) | In progress | Reliable tests, reproducible builds and traceable qualification |
| [M1–M2: State and identities](ROADMAP.md#m1-durable-state-and-operation-recovery) | Partial implementation | Recoverable configuration, complete account ownership and safe credentials |
| [M3–M4: Storage and sharing](ROADMAP.md#m3-complete-storage-discovery-and-volume-lifecycle) | Partial implementation | Stable volume identity and supervised SMB/NFS without fallback writes |
| [M5: Web management](ROADMAP.md#m5-product-web-management-and-security) | Development UI exists | Complete authenticated setup, management and recovery workflows |
| [M6: Network and system services](ROADMAP.md#m6-network-and-system-services) | Planned / hardware-limited | Recoverable networking, time, discovery and system administration |
| [M7: EX4 board and cooling](ROADMAP.md#m7-ex4-board-controller-and-thermal-qualification) | Research only | Qualified peripherals, thermal safety and recoverable boot |
| [M8–M9: Migration and iSCSI](ROADMAP.md#m8-raid-health-and-legacy-migration) | Research / planned | Explicitly supported legacy layouts, health/RAID workflows and guarded LUNs |
| [M10–M11: Installer and release](ROADMAP.md#m10-signed-installer-upgrades-and-recovery) | Host verifier only | Signed model-specific installation, recovery and public beta qualification |

Resource-qualified applications and a possible mobile companion follow the
core NAS release. No release date or completion percentage is promised before
the hardware and recovery gates have evidence.

## Develop without a NAS

Use `develop` for integrated development. Feature branches may contain changes
that have not passed clean CI. No published release is currently a stable
installation branch.

### Fast host checks

Install Git, a local Go **1.26+** toolchain, Node.js and PowerShell. Dependencies
for the Go modules are vendored; the test wrappers disable automatic Go downloads.

```powershell
git clone --branch develop https://github.com/PhantoNull/phantowd-ex4.git
cd phantowd-ex4
.\support\test-api.ps1
.\support\test-lab-tools.ps1
```

These checks do not use Docker or contact the NAS. The API check runs Go
tests/vet and cross-compiles its QEMU-tagged tests for Linux/ARMv5, but does
not execute that binary; it does not replace the Linux guest integration lane.

When the pinned Buildroot image and workspace are already present, run
`support/test-api-linux.ps1` as an additional fast Linux-native check. It runs
`go vet` and the complete API test suite, including Linux-only packages. It
also runs QEMU-tagged `go vet` and a focused Linux `/proc` diagnostic contract.
It mounts the repository and existing Buildroot workspace read-only, disables
network access, uses only an ephemeral container/tmpfs, and fails rather than
pulling an image or creating a volume if the cache is absent. It does not boot
QEMU or replace the full guest integration lane.

### Build and boot the QEMU target

With Docker Desktop running **Linux containers**, run from the repository root:

```powershell
.\support\build-qemu.ps1
```

The first build downloads verified sources and builds the toolchain, kernel
and userspace; allow substantial time and disk space. On Windows, the wrapper
requires at least 40 GiB free on the Docker data drive before starting. It
reuses two fixed Docker volumes (Buildroot workspace and compiler cache), not
new volumes per run; their contents persist and can grow as the source,
downloads, build outputs and cache change. Inspect usage with
`docker system df -v`. When you no longer need the incremental workspace, run
`support/clean-qemu-build-volumes.ps1 -WhatIf` to review the exact targets, then
rerun without `-WhatIf` to remove only those two unreferenced project volumes;
the script prompts before removal. This discards the local Buildroot workspace
and compiler cache but keeps repository artifacts and other Docker data. The
Docker Desktop VHDX may still need separate compaction to return freed space to
the host. Avoid broad Docker prune commands on a shared installation.

Routine API/UI changes should use the no-Docker host checks above; run the full
QEMU build only when guest, kernel, package or integration behavior needs it.
Outputs go to `artifacts/qemu-armv5/`. The smoke tests use disposable virtual storage;
the supported harness does not forward host ports or physical devices.

QEMU exercises ARMv5 software on VersatilePB, **not the EX4 board**. It cannot
validate the EX4's NAND, SATA wiring, fan, display or recovery.
Use the [fast integration lane](support/QEMU-FAST-TESTS.md) for eligible
userspace iterations; clean builds remain required for integration/release.

## Codebase guide

- [Management API and UI](src/phantowd-api/README.md): authentication,
  desired configuration, identity coordination and development fixtures.
- [Storage probe](src/phantowd-volume-probe/README.md): restricted native
  descriptor-based metadata helper.
- [Research toolkit](tools/phantowd-lab/README.md): host-only inspection of
  supplied images, metadata and signed release information.
- [QEMU target](board/qemu/armv5/README.md) and
  [EX4 board research](board/wd/ex4/README.md): separate software and hardware lanes.
- `support/`, `package/`, `configs/`, `.github/workflows/`: build tooling,
  Buildroot integration, configurations and CI.

See [CONTRIBUTING.md](CONTRIBUTING.md) before changing safety-sensitive code.
Keep status, installation claims and roadmap acceptance evidence in sync with
each behavior-changing PR; do not turn this README into a development log.

## License and affiliation

Original project code is Apache-2.0; Linux-derived code remains GPL-2.0-only
and third-party components retain their licenses. See
[LICENSE-POLICY.md](LICENSE-POLICY.md).

This is an unofficial project, not affiliated with or supported by Western
Digital. Do not contribute proprietary WD firmware, device dumps, credentials
or signing keys.
