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

## Follow current development

`main` is the public source snapshot; newer integrated work lives on `develop`.
Neither branch is an installable release. As of **2026-10-07**, promotion of
`develop` is held while failures in the ARMv5 QEMU native Samba lifecycle are
investigated. Passing host tests or compile-only builds do not replace that
integration check.

For the latest integrated scope, see the
[development implementation status](https://github.com/PhantoNull/phantowd-ex4/blob/develop/IMPLEMENTATION-STATUS.md)
and [development roadmap](https://github.com/PhantoNull/phantowd-ex4/blob/develop/ROADMAP.md).
Those documents describe `develop`, not necessarily this checkout. Follow the
[promotion PR](https://github.com/PhantoNull/phantowd-ex4/pull/121) for its exact
commit and check results. Feature-branch work remains unqualified until its
own checks and integration review pass.

## Current capabilities

The current source implements and tests components, not a production appliance.
[Implementation status](IMPLEMENTATION-STATUS.md) records exact verification
scope; [component contracts](src/phantowd-api/README.md) describe the boundaries.

| Area | Implemented / tested | Still needed for the product |
| --- | --- | --- |
| Build | Pinned Buildroot 2025.02.18 LTS / Linux 6.18.54 LTS, ARMv5 QEMU image, SBOM, development source collection and automated tests | Installable EX4 image, complete release source bundle and qualification |
| Web management | Bounded read-only snapshots, development administrator authentication/password changes, SMB/NFS policy editing with before/after review and cross-protocol folder advisories | Complete setup/recovery, certificate lifecycle, browser qualification and live service management |
| Storage | Non-root read-only broker, complete sysfs inventory, manual GPT observations, duplicate-identity detection, protected registry with reader-bound rechecks, rechecked registry/census policy and backing reviews, internal MD/mount-owner fixtures | Trusted production lifecycle, persistent volume IDs, global-use accounting, qualified import and RAID management |
| Sharing and identities | SMB3/NFS fixtures, disabled-first Samba account lifecycle, session revocation, Unicode/CP850, streams and POSIX ACL tests | Product account workflows, supervised service activation/recovery and legacy permission migration |
| iSCSI | Coherent desired policy, root-only CHAP reader, registry/share review, private declared SMB/NFS exposure refusal, shared backing-object reservations and retained-storage LIO/CHAP composition with ARMv5 access/session/fault fixtures | Product authority/composition, credential provisioning/recovery, external/cross-protocol use and complete session guards, import and target-management UI |
| Health | Bounded SMART interpretation, generation-bound coordinator, private complete sysfs census including in-use disks, retained descriptor-generation witness, subprocess replay and native/ARMv5 synthetic producer fixtures | Qualified command/device provider, report-to-device binding, history, authorized test jobs, notifications and UI |
| Network policy | Desired dual-stack policy, private read-only kernel inventories and internal local-address conflict diagnostics in host/ARMv5 QEMU | Qualified physical interface binding, external address-conflict/routing admission, persistent trial/confirmation/rollback and management UI |
| Service isolation | Static-child owner/grant isolation, bounded-privilege Samba fixture with retained code/configuration, mutable-state directory lifetimes and descriptor handoff, separate read-only code/service views with copied-object refusal, verified code staging, offline ARM-header/build-attribute observations, actual QEMU libatomic dispatch tests and supervised retained static-code Owner | Product-authorized runtime inputs, complete descriptor-bound construction, identity/state/storage composition, durable recovery and product startup |
| EX4 hardware | Bounded diskless RAM research; see [board notes](board/wd/ex4/README.md) | Sustained networking, factory MAC handoff, SATA, cooling, LEDs/display, thermal safety and recovery |

The API/dashboard are development-only and guest-loopback-only by default.
Do not expose them through a LAN listener or reverse proxy. Service experiments
and mount fixtures are not enabled for user disks. Desired configuration and
successful parser checks do not activate a product service.

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
| [M10–M11: Installer and release](ROADMAP.md#m10-signed-installer-upgrades-and-recovery) | Host verifier only | Signed model-specific installation, recovery and public beta qualification |

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
or creating volumes. Use the [fast integration lane](support/QEMU-FAST-TESTS.md)
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
- [Research toolkit](tools/phantowd-lab/README.md): host-only image, metadata and
  signed-release inspection.
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
