<p align="center">
  <img src=".github/assets/phantowd-ex4-banner.png" alt="PhantoWD EX4: a four-bay NAS with orange ghost branding" width="700">
</p>

# PhantoWD EX4

Community replacement firmware research for the **WD My Cloud EX4**.
The goal is a maintained NAS with local web management, modern file sharing
and recoverable updates.

[![QEMU integration](https://github.com/PhantoNull/phantowd-ex4/actions/workflows/qemu-armv5.yml/badge.svg?branch=develop)](https://github.com/PhantoNull/phantowd-ex4/actions/workflows/qemu-armv5.yml?query=branch%3Adevelop)

## Status

**Research only: compile-only, `flashable=no`. Not installable on an EX4.**
The [research release](https://github.com/PhantoNull/phantowd-ex4/releases/tag/v0.1.0-research.1)
contains signed research artifacts, not a WD dashboard update or supported
installation procedure. Do not flash them or attach valuable disks to an
experimental image.

| Area | Current scope |
| --- | --- |
| Software | ARMv5/QEMU tests cover storage discovery, identities, configuration, SMB/NFS and iSCSI components. |
| Web management | Development dashboard; complete appliance setup and live service management remain unfinished. |
| EX4 hardware | Board research; storage, sustained networking, fan, LEDs/display and recovery are not product-qualified. |
| Installation | Host-side release verification and planning only; no supported device installation or disk migration. |

See [implementation status](IMPLEMENTATION-STATUS.md) for component evidence,
[storage compatibility](STORAGE-COMPATIBILITY.md) for disk-layout limits and
[the roadmap](ROADMAP.md) for remaining work. QEMU emulates generic ARMv5,
not the EX4 peripherals; passing it does not qualify physical hardware.

## Development

Use `develop` for integration and `main` for promoted research snapshots.
Read [CONTRIBUTING.md](CONTRIBUTING.md) for prerequisites and validation rules;
source versions are pinned in [versions.env](versions.env).

```powershell
git clone --branch develop https://github.com/PhantoNull/phantowd-ex4.git
cd phantowd-ex4
.\support\test-api.ps1
.\support\test-lab-tools.ps1
```

These host checks need no NAS or Docker. For ARMv5 integration, use
`support/build-qemu.ps1` with Docker Linux containers; see the
[build and cache guide](support/QEMU-FAST-TESTS.md) before starting a build.

## Technical documentation

- [Management API and dashboard](src/phantowd-api/README.md)
- [Storage probe](src/phantowd-volume-probe/README.md)
- [Host research tools](tools/phantowd-lab/README.md)
- [EX4 board research](board/wd/ex4/README.md)

## License

Original code is Apache-2.0; kernel-derived and third-party code retain their
licenses. See [LICENSE-POLICY.md](LICENSE-POLICY.md).
This project is unofficial and is not affiliated with Western Digital.
Do not contribute proprietary firmware, device dumps, credentials or private keys.
