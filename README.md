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
- design signed, model-specific updates with rollback protection.

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

The first product-owned package is a [read-only diagnostics API](src/phantowd-api/README.md).
It runs unprivileged on guest loopback only, has no storage/hardware controls,
and has no authentication/TLS yet. The QEMU test checks its ARMv5 metadata,
GET/negative request contract, and a smoke-only RSS ceiling. Guest networking
is restricted and no ports or physical devices are forwarded.
Run `.\support\test-api.ps1` for fast offline host-native tests; the complete
build runs those tests again with Buildroot's hash-verified Linux Go compiler.

The [offline research toolkit](tools/phantowd-lab/README.md) validates user-supplied
local copies of the legacy WD update, logical-mtd3 and redacted logical-rescue
formats, replays passive controller captures, and scans extracted trees for
known legacy storage-path literals. It also validates a project-owned,
versioned synthetic storage-inventory JSON and generic GPT structure in
caller-supplied image files, with optional read-only ext-family superblock or
Linux MD v1.2 and v0.90 component-superblock checks for selected GPT
partitions, plus a direct Linux MD 0.90 component-image check. These are not
WD XML parsers or WD disk-layout compatibility detectors; valid partition,
filesystem, or single-member RAID metadata does not establish that a disk can
be migrated safely. Artifact inspectors accept regular files only;
extracted-tree tools do not follow symlinks or open special files. The path
scan is not full code analysis. The toolkit has no firmware
extraction, image construction, flash-device, serial-port, or transmit path.
Run `.\support\test-lab-tools.ps1` for its generated-fixture test suite. No
proprietary firmware or device dump is included in the repository.

A separate compile-only Linux 6.18 EX4 device-tree baseline is available with
`.\support\build-ex4-dtb.ps1`. It intentionally disables raw NAND and SDIO,
and its output under `artifacts/ex4-dtb-research/` is also non-flashable.

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

Development follows a read-only-first policy. Initial physical bring-up must
use non-persistent boot paths and must not involve user-data disks or NAND
writes.

## Repository layout

- `board/wd/ex4/` — board notes and future Buildroot board support;
- `board/qemu/armv5/` — non-flashable ARMv5 software test target;
- `configs/` — reproducible Buildroot defconfigs;
- `support/` — pinned container build and QEMU smoke-test tooling;
- `tools/phantowd-lab/` — host-only read-only format and protocol tooling;
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

Original PhantoWD source code, build tooling, and documentation are licensed
under Apache-2.0. Linux-derived device trees and kernel changes remain
GPL-2.0-only, and third-party components retain their upstream licenses.
See [LICENSE-POLICY.md](LICENSE-POLICY.md) and `REUSE.toml` for the per-file
rules.

Vendor firmware, keys, device dumps, proprietary binaries, and other
non-redistributable artifacts must not be committed.
