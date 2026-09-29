<p align="center">
  <img src=".github/assets/phantowd-ex4-banner.png" alt="PhantoWD EX4: a four-bay NAS with orange ghost branding" width="700">
</p>

# 👻 PhantoWD EX4

A community replacement firmware project for the **WD My Cloud EX4**:
a maintained, local-first NAS with a web management interface, modern file
sharing, recoverable updates, and a conservative migration path for existing
disks.

[![QEMU integration build](https://github.com/PhantoNull/phantowd-ex4/actions/workflows/qemu-armv5.yml/badge.svg?branch=develop)](https://github.com/PhantoNull/phantowd-ex4/actions/workflows/qemu-armv5.yml?query=branch%3Adevelop)
[Roadmap](ROADMAP.md) · [Contributing](CONTRIBUTING.md) ·
[Builds](https://github.com/PhantoNull/phantowd-ex4/actions/workflows/qemu-armv5.yml) ·
[Releases](https://github.com/PhantoNull/phantowd-ex4/releases)

## Can I install it?

**Not yet. There is no installable PhantoWD firmware release or supported
upgrade procedure.** CI artifacts are development/test outputs, not WD
dashboard updates. Do not flash them, replace NAND partitions, or attach
valuable disks to an experimental image.

You can develop and test the software in QEMU without connecting a NAS.
Physical EX4 work is still restricted to separately reviewed research tests.
A public installer will require qualified board support, storage compatibility,
signed updates, and demonstrated recovery.

## What works today?

These capabilities describe this source revision; they are not a claim of a
production-ready appliance.

| Area | Available now | Not yet qualified |
| --- | --- | --- |
| Build | Pinned Buildroot 2025.02.18 / Linux 6.18.53; ARMv5 QEMU image, package SBOM and automated tests | Installable EX4 image and release qualification |
| Web interface | Diagnostics, development administrator authentication/password changes, SMB/NFS policy previews and opt-in policy editing | Product setup/recovery, certificate lifecycle and live service administration |
| File services | Real isolated SMB3/NFS tests and clean-reboot fixtures; root-only M2.3 Samba patch merged as `33df1ed`; M2.4 journaled disabled-first enrollment, disabled password assignment and explicit enable/disable/re-enable through an Owner-bound executor and credential-bearing Unix-socket v2 fixture; QEMU-only Owner boot/socket lifecycle tests; local M2.5 full ARMv5 QEMU verifies journaled disable denies new logins and revokes only that account's sessions while preserving a same-IP peer; uncertain outcomes enter review without replay; no AD-DC or HTTP endpoint | Product startup/config and socket wiring, HTTP authorization binding, operator recovery, account lifecycle UI and retirement; in-flight write/open-handle/durable-reconnect semantics and safe product service activation remain unqualified |
| Storage | Read-only schema-v2 metadata and complete-inventory discovery; separate non-root broker with read-only device rules, `no_new_privs` and zero capabilities. PR #44's mounted filesystem UUID / MD correlation passed exact-head host, Stage B3 and ARMv5 QEMU checks and merged as `db9fd33`. Local M3.2a/b/c/d adds private GPT correlation and duplicate classification, generic declaration hints, plus a dashboard-triggered, authenticated manual `POST /api/v1/storage/gpt-observation`; page load and ordinary refresh never scan GPT metadata. It uses a fixed broker operation and displays only redacted aggregate results. The local ARMv5 QEMU smoke exercises this POST through the real broker on two distinct read-only synthetic GPT clones, verifies duplicate GUID/PARTUUID classification, and checks aggregate-only redaction. Full local Buildroot/package integration, QEMU smoke and the state-reboot fixture passed on `1358202`; artifact SHA-256 checks passed. The run reused the fixed Buildroot/cache volumes and does not establish independent clean-build reproducibility. MBR remains unsupported; errors return no partial result. No mount/import/repair/write action is authorized. The host-only image research tool now also reads and compares generic MD v1.0 metadata, matching the data-array creation mode found in the extracted stock installer scripts; this is offline format evidence only, not EX4 compatibility qualification. The mountguard now permanently closes its own pinned Root after an identity/state check fails; this does not revoke returned descriptors or dependent services and is not product lifecycle qualification. Desired SMB/NFS policy uses distinct logical `VolumeID` and expected `FilesystemUUID` types, but no persistent resolver exists. | Hosted CI and EX4 qualification remain pending; host/QEMU fixtures are not hardware qualification. Content reads, mount/import, global-use accounting, persistent identity, supported WD import and product RAID management remain unqualified or unimplemented |
| EX4 hardware | Short diskless RAM boots, limited Ethernet and internal-temperature observations | Sustained dual-port networking, cooling/controller, storage and recovery |

A focused local ARMv5 QEMU check now compares mdadm-authored MD v1.0 metadata
against the host parser using only two temporary 32 MiB members in tmpfs. It
does not format or mount a filesystem and is not EX4 compatibility or hardware
qualification; see the [fast test instructions](support/QEMU-FAST-TESTS.md).

Read-only storage discovery now refuses the entire assessment before opening
candidate disks if a nonzero mount device number cannot be mapped to the
complete sysfs block inventory. This is still a point-in-time, current-namespace
check, not proof of global storage-use exclusivity or EX4 qualification.

The current-source local ARMv5 API overlay on `develop` `0f2e44e` subsequently
passed the M3.2a and mount-guard QEMU smoke plus the separate two-boot
state-reboot fixture, using cached kernel/packages and a schema-v2 helper. This
is fast local overlay evidence, not a clean Buildroot rebuild, hosted CI, or EX4
qualification.

The host-only `phantowd-lab inspect-storage-image-set` tool now correlates
bounded GPT, ext and Linux MD v1.2, v1.0 and 0.90 metadata across supplied
whole-disk image files, redacts identities, and withholds cross-image
conclusions when a GPT input is invalid. Its results are generic evidence only:
WD compatibility stays unqualified and migration, assembly and mounting are
never authorized.

The API and dashboard remain development-only and guest-loopback-only by
default. Do not expose them through a LAN listener or reverse proxy.
[Component contracts](src/phantowd-api/README.md) explain the precise boundaries.

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
mounts the repository and existing Buildroot workspace read-only, disables
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
