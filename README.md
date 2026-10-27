<p align="center">
  <img src=".github/assets/phantowd-ex4-banner.png" alt="PhantoWD EX4: a four-bay NAS with orange ghost branding" width="700">
</p>

# 👻 PhantoWD EX4

A community replacement firmware project for the **WD My Cloud EX4**:
a maintained, local-first NAS with web management, modern file sharing,
recoverable updates and a conservative migration path for existing disks.

[![QEMU integration build](https://github.com/PhantoNull/phantowd-ex4/actions/workflows/qemu-armv5.yml/badge.svg?branch=develop)](https://github.com/PhantoNull/phantowd-ex4/actions/workflows/qemu-armv5.yml?query=branch%3Adevelop)
[Roadmap](ROADMAP.md) · [Implementation status](IMPLEMENTATION-STATUS.md) ·
[Contributing](CONTRIBUTING.md) · [Builds](https://github.com/PhantoNull/phantowd-ex4/actions/workflows/qemu-armv5.yml) ·
[Releases](https://github.com/PhantoNull/phantowd-ex4/releases)

## Can I install it?

**Not yet. There is no installable firmware release or supported upgrade
procedure.** CI artifacts are development/test outputs, not WD dashboard
updates. Do not flash them, replace NAND partitions or attach valuable disks
to an experimental image.

No legacy disk layout is product-qualified for migration; see the
[storage compatibility matrix](STORAGE-COMPATIBILITY.md). A public installer
requires qualified board support, disk compatibility, signed updates and
demonstrated recovery. Development and QEMU testing do not require a NAS.

## Current capabilities

The current source implements and tests components, not a production appliance.
[Implementation status](IMPLEMENTATION-STATUS.md) records exact verification
scope; [component contracts](src/phantowd-api/README.md) describe the boundaries.

| Area | Implemented / tested | Still needed for the product |
| --- | --- | --- |
| Build | Pinned Buildroot 2025.02.18 LTS / Linux 6.18.55 LTS; complete local ARMv5 integration and exact source/image/SBOM audit pass | Exact-head hosted checks, independent clean reproduction, installable EX4 image and release qualification |
| Web management | Byte-bounded read-only snapshots with independent display validation and invalid/empty-inventory distinction, development authentication/password changes, SMB/NFS policy editing, configuration download and reviewed restore with explicit revisioned save, sanitized snapshot report export | Complete setup/recovery, certificate lifecycle, browser/accessibility qualification and live service management |
| Storage | Non-root read-only broker, complete sysfs inventory, manual GPT observations, duplicate-identity detection, protected registry with reader-bound rechecks, rechecked registry/census policy and backing reviews, internal MD/mount-owner fixtures | Trusted production lifecycle, persistent volume IDs, global-use accounting, qualified import and RAID management |
| Sharing and identities | SMB3 fixtures and NFSv3/TCP read/write across clean guest lifetimes, opt-in Linux NAS-policy API with authenticated HTTPS and a retained non-root client against the original root Owner, stored-policy NFS activation and explicit read-only to read-write reactivation with fresh claims and update exclusion, disabled-first Samba accounts, session revocation, retained same-authority SMB startup/access, exclusive supervision, held-session and original-open-file source-loss, verified client/daemon closure, Unicode/CP850, streams and POSIX ACL tests | Product state/API bootstrap and dashboard wiring, account workflows, complete fault coverage, supervised service activation/recovery and legacy permission migration |
| iSCSI | Coherent desired policy, root-only CHAP reader, registry/share review, private declared SMB/NFS exposure refusal, shared backing-object reservations and retained-storage LIO/CHAP composition with ARMv5 access/session/fault fixtures | Product authority/composition, credential provisioning/recovery, external/cross-protocol use and complete session guards, import and target-management UI |
| Health | Bounded SMART interpretation, generation-bound coordinator, private complete sysfs census including in-use disks, retained descriptor-generation witness, subprocess replay and native/ARMv5 synthetic producer fixtures | Qualified command/device provider, report-to-device binding, history, authorized test jobs, notifications and UI |
| Network policy | Desired dual-stack policy, private read-only kernel inventories and internal local-address conflict diagnostics in host/ARMv5 QEMU | Qualified physical interface binding, external address-conflict/routing admission, persistent trial/confirmation/rollback and management UI |
| Service isolation | Static-child owner/grant isolation, bounded-privilege Samba fixture with retained code/configuration, mutable-state directory lifetimes and descriptor handoff, separate read-only code/service views with copied-object refusal, verified code staging, offline ARM-header/build-attribute observations, actual QEMU libatomic dispatch tests and supervised retained static-code Owner | Product-authorized runtime inputs, complete descriptor-bound construction, identity/state/storage composition, durable recovery and product startup |
| EX4 hardware | Bounded diskless RAM research; see [board notes](board/wd/ex4/README.md) | Sustained networking, factory MAC handoff, SATA, cooling, LEDs/display, thermal safety and recovery |
| Release tooling | Host-only unsigned manifest producer, bounded GitHub reader, signature/payload verification and verify-only logical installation preview with mandatory write refusal | Trusted provenance/staging, key provisioning/signing, physical layout, target transaction, recovery and release qualification |

The API/dashboard are development-only and guest-loopback-only by default.
The dashboard can manually read compact counts from the coherent NAS policy;
these are saved definitions, not running-service status or activation.
It can also download all SMB/NFS/iSCSI definitions in one versioned JSON file,
preserving 64-bit values. Data and credential backups remain separate.
With the opt-in NAS-policy channel configured, the existing SMB/NFS editor,
backup and restore preview share that same Owner; saves preserve iSCSI policy.
Do not expose them through a LAN listener or reverse proxy. Service experiments
and mount fixtures are not enabled for user disks. Desired configuration and
successful parser checks do not activate a product service.

Configuration transaction fixtures also pass ARMv5 interrupted-writer,
full-ext4 and read-only-ext4 tests with confirmed policy retained. This is not
power-loss recovery or qualification of the EX4's physical state medium.
A separate internal read-only observer distinguishes current policy and
incomplete evidence without initialization, recovery or service admission.
Its empty-directory result is not proof that the NAS is pristine.
An internal read-only lifetime also retains its lock and original references
between observations, refusing further reads after drift or uncertainty.

A separate ARMv5 fixture now verifies a retained, isolated real SMB3 client
opening and closing synthetic data without changes or leaked descriptors.
Its independent server-side snapshots now match the same worker generation,
session, tree and open to the retained local file. The original client/worker
processes, retained namespaces and reciprocal TCP connection now also match.
Two one-byte READs now also match kernel-credentialled VFS metadata against
the original client FileIds and independent worker/local-file observations.
A retained worker file-object pin is not a duplicate open-file description
or request lease; complete faults and product activation remain unqualified.
An optional composed guest now observes the original client handle and matches
its session/tree to the independent server witness. Remote-FileId-to-local-object
matching is observed only in that fixture; request binding remains unqualified.
A separate peer-stop fixture also verifies client refusal, sticky review and
original-reference retention with unchanged data and verified subprocess disposal.
An original-worker loss fixture verifies the same refusal/retention between
completed read requests, without claiming interruption of pending I/O.
Module/configuration substitutions and receiver drift also retain review after
restoration in dedicated disposable fixtures; they do not authorize a service.
A missing-READ-acknowledgement fixture additionally verifies stopped processes,
sticky review and an unconsumed queued record, without certifying completion.
A canceled-collection fixture additionally verifies bounded observer settlement
and the same review/queue retention, not interruption of server I/O.
A parent source-leaf substitution fixture rejects a byte-identical replacement
against the original held object and preserves review after restoration.
A fixed parent-share fixture also rejects a new mount of the same directory:
equal content and inode do not replace the original unique mount identity.
It does not qualify pending writes, recovery or product service activation;
see the [focused test contract](support/QEMU-FAST-TESTS.md#dedicated-same-open-client-prerequisites-host-and-qemu).

The code-only inspector rejects undeclared entries, incorrect hashes/modes,
cross-mount or symlink traversal, file capabilities and access/default ACLs.
This rule is separate from supported **data-share ACLs**. Its point-in-time
observation is not a signed manifest, retained lease or execution authority.
See the [runtime contract](src/phantowd-api/internal/runtimebundle/README.md) and
[Samba profile](support/SAMBA-RUNTIME-PROFILE.md).

The build badge tracks `develop`, not every feature branch. Check a workflow's
commit, conclusion and artifacts before relying on it. Cached local tests do
not establish independent clean-build reproducibility, complete licensing
compliance or physical EX4 qualification. [versions.env](versions.env) is the
source of truth for build pins.

The builder selects host OpenSSL 3.5.9 with exact recipe/hash and installed
CLI/library guards. Its complete cached integration and independent artifact/
source/license/SBOM audit pass. This does not enable target OpenSSL or qualify
a NAS HTTPS service, independent clean reproduction or physical EX4 support.

The latest fully audited local code checkpoint, `5245ada`, selects Go 1.26.8 and
host OpenSSL 3.5.9. Complete cached host/ARMv5 integration, all ten independently
enrolled Samba guests and both synthetic SMART lanes pass. The sharing fixtures
cover same-authority startup, real data access, exclusive supervision, verified
closure and idle original-session/open-file faults with retained review and no
restart. Source restoration does not release reviewed authority. These are not
pending-I/O, physical disk failure, durable reconnect or recovery qualifications.

An independent audit matches all 1,067 API inputs, actual images, kernel/header
archives, the selected and installed Go SDK, release metadata, SBOM and declared
license files. OpenSSL's three installed objects are byte-exact reproductions
of their built objects after Buildroot's configured RPATH normalization. The
actual Buildroot Python consumer loads those libraries and passes certificate
verification and private loopback TLS 1.3; see the
[exact qualification record](support/DEPENDENCY-REVIEW.md).
This does not establish independent clean reproduction, physical EX4 support,
complete fault coverage or an installable release. The native QEMU fixture now
separates preparation from enrollment and preserves the cause of incomplete
revocation observations. Behavioral regression tests and the complete local
lane pass; the integration PR still requires new-head hosted qualification.
An earlier hosted QEMU run failed at a later live-session deadline;
local success does not establish a hosted timing fix or waive that gate.
The earlier complete candidate's final source-loss deadline remains unexplained;
this newer complete pass is not a demonstrated timing fix. The combined candidate
must pass its own hosted checks before integration. No product
SMB/NFS service is activated; see [implementation status](IMPLEMENTATION-STATUS.md).

## Roadmap

The detailed [roadmap](ROADMAP.md) specifies task IDs, dependencies, acceptance
tests, failure handling and contributor handoffs.

| Milestone | Current state | Intended outcome |
| --- | --- | --- |
| [M0: Engineering baseline](ROADMAP.md#m0-engineering-baseline-and-test-reliability) | In progress | Reliable tests, reproducible builds and traceable qualification |
| [M1–M2: State and identities](ROADMAP.md#m1-durable-state-and-operation-recovery) | Partial implementation | Recoverable configuration, account ownership and safe credentials |
| [M3–M4: Storage and sharing](ROADMAP.md#m3-complete-storage-discovery-and-volume-lifecycle) | Partial implementation | Stable volumes and supervised SMB/NFS without fallback writes |
| [M5: Web management](ROADMAP.md#m5-product-web-management-and-security) | Development UI | Authenticated setup, management and recovery workflows |
| [M6: Network and system services](ROADMAP.md#m6-network-and-system-services) | Desired model tested; apply planned | Recoverable networking, time, discovery and administration |
| [M7: EX4 board and cooling](ROADMAP.md#m7-ex4-board-controller-and-thermal-qualification) | Research | Qualified peripherals, thermal safety and recoverable boot |
| [M8–M9: Health, migration and iSCSI](ROADMAP.md#m8-raid-health-and-legacy-migration) | Offline inspectors; management planned | SMART monitoring/tests, notifications, RAID, supported legacy layouts and guarded LUNs |
| [M10–M11: Installer and release](ROADMAP.md#m10-signed-installer-upgrades-and-recovery) | Host metadata producer/verifier only | Signed model-specific installation, recovery and public beta qualification |

Resource-qualified applications and a possible mobile companion follow the
core NAS release. No release date or completion percentage is promised before
the hardware and recovery gates have evidence.

## Develop without a NAS

Use `develop` for integrated development. Feature branches may not have passed
clean CI; no published release is a stable installation branch.
Read [CONTRIBUTING.md](CONTRIBUTING.md) before changing safety-sensitive code.

### Fast checks

Install Git, Go **1.26+**, Node.js and PowerShell. Go dependencies are vendored;
the test wrappers disable automatic toolchain downloads.

```powershell
git clone --branch develop https://github.com/PhantoNull/phantowd-ex4.git
cd phantowd-ex4
.\support\test-api.ps1
.\support\test-lab-tools.ps1
```

These checks do not use Docker or contact the NAS. ARMv5 cross-compilation is
not guest execution. With the pinned image/workspace already present,
`support/test-api-linux.ps1` adds Linux-native checks without pulling an image
or creating volumes. Its non-root container is capped at four CPUs, 2 GiB RAM,
256 processes and 1 GiB disposable tmpfs; the Linux suite has a 180-second
timeout with a 10-second termination grace. A timeout is a failure, not a retry.
Use the [fast integration lane](support/QEMU-FAST-TESTS.md)
for eligible userspace changes; clean builds remain separate qualification.

### Build and boot QEMU

With Docker Desktop running **Linux containers**, run from the repository root:

```powershell
.\support\build-qemu.ps1
```

The first build downloads verified sources and builds the toolchain, kernel
and userspace. The Windows wrapper requires at least 40 GiB free on Docker's
data drive. It reuses two fixed volumes; inspect their usage with
`docker system df -v`. Avoid broad Docker prune commands on shared systems.

For repeated local full validation with the **current configuration already
initialized**, use `support/build-qemu.ps1 -CachedOnly`. It refuses missing
images/volumes/toolchain, performs no image build/pull or explicit volume
creation, and bypasses ownership repair. One auto-removed non-root container
uses a bounded CPU/memory/PID profile and disposable RAM test caches/scratch;
the existing Buildroot output and compiler cache remain reusable. See the
[local validation contract](support/QEMU-FAST-TESTS.md#bounded-cached-full-validation).
This is still the complete integration lane, not the faster overlay lane or
independent clean-build qualification. Do not run concurrent builds against the
same workspace or edit the tested source while a run is active.

Outputs are in `artifacts/qemu-armv5/`. Tests use disposable virtual storage,
without host-port forwarding or physical devices. QEMU emulates ARMv5 on
VersatilePB, **not the EX4's NAND, SATA, fan, display or recovery**.

When discarding the cached workspace is acceptable, review
`support/clean-qemu-build-volumes.ps1 -WhatIf`, then rerun without `-WhatIf`
to remove only the two unreferenced project volumes. Repository artifacts and
unrelated Docker resources remain; Docker's VHDX may need separate compaction.

## Codebase guide

- [Management API/UI](src/phantowd-api/README.md): authentication, configuration,
  identity coordination and development fixtures.
- [Storage probe](src/phantowd-volume-probe/README.md): restricted descriptor-based
  metadata helper.
- [Research toolkit](tools/phantowd-lab/README.md): host tools for image metadata,
  generic DOS primary entries and signed releases.
- [QEMU target](board/qemu/armv5/README.md) and
  [EX4 board research](board/wd/ex4/README.md): separate software/hardware lanes.
- `support/`, `package/`, `configs/`, `.github/workflows/`: tooling,
  Buildroot integration and CI.

Keep implementation status, installation claims and roadmap evidence in sync
with behavior-changing PRs. Test history belongs in component/status documents,
not this overview.

## License and affiliation

Original project code is Apache-2.0; Linux-derived code remains GPL-2.0-only
and third-party components retain their licenses. See
[LICENSE-POLICY.md](LICENSE-POLICY.md).

This unofficial project is not affiliated with or supported by Western Digital.
Do not contribute proprietary WD firmware, device dumps, credentials or signing keys.
