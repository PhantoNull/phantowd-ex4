# 👻 PhantoWD EX4

PhantoWD EX4 is an unofficial, community-oriented effort to give the
unsupported WD My Cloud EX4 a maintainable software base. The intended target
is a small Buildroot system with modern, deliberately selected components,
reproducible builds, safe recovery, and signed model-specific updates.

The project is at the **hardware discovery and non-destructive bring-up**
stage. It does not yet produce a flashable replacement firmware. It now has a
separately named ARMv5 QEMU baseline for software-only development.

## Current work

- document the boot chain, flash layout, NAND/ECC behaviour, and peripherals;
- preserve a verified recovery path before changing persistent flash;
- reproduce the vendor kernel and user-space layout from legally obtained
  inputs without redistributing proprietary WD binaries;
- bring up a Buildroot image in RAM or over the network first;
- design signed, model-specific updates with rollback protection;
- keep a legacy NFS integration available while replacement-firmware work is
  in progress.

## Pinned QEMU baseline

The source baseline is pinned to Buildroot 2025.02.18 and Linux 6.18.50. The
Buildroot release signature, signing-key fingerprint, Buildroot archive hash,
and Linux archive hash are verified before use. On Windows with Docker Desktop:

```powershell
.\support\build-qemu.ps1
```

The build must reach the `PHANTOWD_QEMU_READY` marker on an emulated ARM926
CPU. Resulting files under `artifacts/qemu-armv5/` are explicitly non-flashable.
They test the ARMv5 software foundation only; QEMU does not emulate the EX4's
NAND, SATA, fan, display, LEDs, watchdog, buttons, or management controller.

`BR2_REPRODUCIBLE` is enabled, but bit-for-bit reproducibility is not claimed
until two clean builds in independently provisioned environments have been
compared. The container base image is digest-pinned; Debian build-dependency
packages are not yet tied to an immutable snapshot.

The project mascot and future logo are a small ghost: the **PhantoWD**.

## Safety status

Do not write to `/dev/mtd3`, `/dev/mtdblock3`, or any other flash partition
using material from this repository. A SquashFS signature at a particular
offset is not proof that a NAND partition can be copied or rewritten as a flat
file. Bad-block handling, ECC/OOB data, WD headers, validation, and rescue
behaviour must all be understood first.

The current lab device is still serving data. Development therefore follows a
read-only-first policy, and initial boot experiments must avoid NAND writes.

## Repository layout

- `board/wd/ex4/` — board notes and future Buildroot board support;
- `board/qemu/armv5/` — non-flashable ARMv5 software test target;
- `configs/` — reproducible Buildroot defconfigs;
- `support/` — pinned container build and QEMU smoke-test tooling;
- `contrib/legacy-nfs/` — current legacy-firmware NFS persistence helpers;
- `doc/` — private runtime wiki, intentionally ignored by Git;
- `Config.in`, `external.mk`, `external.desc` — Buildroot external-tree
  skeleton.

## Scope

The first hardware target is the WD My Cloud EX4 running vendor firmware
2.13.108 on ARMv5/Feroceon hardware. Support for other models must use separate
board definitions and separately built update artifacts; there will be no
"universal" image selected only at install time.

This project is not affiliated with, endorsed by, or supported by Western
Digital. WD and My Cloud are trademarks of their respective owner.

## Licensing

No project-wide software license has been selected yet. Until one is added,
the repository is source-available for review but grants no general reuse
license. Contributions must retain upstream copyright and license notices.
Vendor firmware, keys, device dumps, and other proprietary artifacts must not
be committed.
