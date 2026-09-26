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
| File services | Real isolated SMB3/NFS tests, access checks and clean-reboot fixtures; native identity coordination libraries | End-to-end product account/credential management and safe service activation |
| Storage | Read-only metadata inspection and descriptor-based identity checks | Complete device discovery, supported WD import, RAID management and data-disk compatibility |
| EX4 hardware | Short diskless RAM boots, limited Ethernet and internal-temperature observations | Sustained dual-port networking, cooling/controller, storage and recovery |

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

These checks do not contact the NAS. They do not replace Linux-specific or
ARMv5 integration tests.

### Build and boot the QEMU target

With Docker Desktop running **Linux containers**, run from the repository root:

```powershell
.\support\build-qemu.ps1
```

The first build downloads verified sources and builds the toolchain, kernel
and userspace; allow substantial time and disk space. The wrapper retains
Docker build/cache volumes between runs. Outputs go to
`artifacts/qemu-armv5/`. The smoke tests use disposable virtual storage;
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
