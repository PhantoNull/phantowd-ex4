# WD My Cloud EX4 board support

This directory is reserved for board-specific Buildroot support: kernel and
bootloader configuration fragments, device-tree work, root-filesystem overlay,
post-build scripts, image assembly, and recovery documentation.

Known discovery baseline:

- vendor firmware 2.13.108;
- Linux 3.2.40;
- ARMv5/Feroceon-class CPU;
- approximately 512 MiB RAM;
- raw NAND containing U-Boot, kernel, ramdisk, main image, rescue firmware,
  persistent config, and reserve partitions.

These facts are not sufficient to build or flash an image. Before board support
is enabled, determine CPU/SoC identity, RAM map, UART parameters, NAND geometry,
ECC/OOB layout, bad-block behaviour, Ethernet/SATA/USB controllers, GPIOs,
fan/thermal control, LEDs, buttons, watchdog, RTC, and bootloader environment.

Initial bring-up must boot from RAM, TFTP, or another non-persistent path.

## Linux 6.18 device-tree research baseline

`patches/linux/0001-arm-dts-marvell-add-wd-my-cloud-ex4-baseline.patch`
adds a compile-only EX4 device tree to the pinned Linux source. It is derived
from bodhi's GPL-2.0 community work with exact source URLs and hashes recorded
in the patch.

The baseline enables only the CPU-visible devices supported by current
evidence. Raw NAND and SDIO are explicitly disabled because two published NAND
unit-address names are malformed, write/ECC behavior remains unqualified, and
the SDIO pin group conflicts with UART1.
Fan, LCD, disk LEDs, buttons, RTC integration, watchdog policy, and safe power
control are not represented yet.

Compile and test the patch on Windows with Docker Desktop:

```powershell
.\support\build-ex4-dtb.ps1
```

The resulting `artifacts/ex4-dtb-research/` directory is ignored by Git and
contains a prominent non-flashable warning. Successful compilation is not
hardware validation and does not make the DTB safe to boot.

## Stage A compile-only safety target

`configs/phantowd_ex4_stage_a_defconfig` is a separate built-in-initramfs
target for the first future serial-only RAM bring-up. Its kernel configuration
removes the block layer, MTD, network, USB, MMC, SCSI, ATA, mdraid, device
mapper, modules, CPU frequency/idle transitions, direct physical-memory access
and optional hardware classes. Mainline `MACH_KIRKWOOD` forces the unused PCI
core plus generic GPIO/SATA-PHY support to remain compiled in. The PCIe host
driver is compiled out, while the DTB explicitly disables the PCIe controller,
both GPIO controllers, both SATA PHY nodes and every other known non-console
peripheral. ARM also retains two inert 8250 support helpers around the required
serial console.

The Stage A initramfs also uses a dedicated all-disabled BusyBox configuration
that enables only `ash`/`sh`, `mount`, `uname`, `sleep`, and `halt`. The build
checks both the final BusyBox configuration and the installed applet symlinks,
so tools capable of inspecting, networking, or modifying storage cannot enter
this probe image through the normal Buildroot defaults. Post-build pruning
also removes the generic skeleton's dormant network hooks and every shared
library except the ELF loader and `libc` required by the audited BusyBox
binary; exact dependency and executable-file allowlists are checked.

Build and statically verify it with:

```powershell
.\support\build-ex4-stage-a.ps1
```

The output is deliberately labelled compile-only. It does not prove U-Boot
load addresses, boot commands, pinmux, clocks, thermal behavior, halt behavior
or recovery, and must not be used on hardware before those gates are reviewed.

Buildroot embeds the generated `rootfs.cpio` in `zImage`; the separate CPIO is
retained only for static inspection. Linux's appended-DTB and ATAG-compatibility
options are enabled for this old-bootloader research path, and the verifier
also emits `zImage-with-appended-dtb.compile-only`: exactly the raw `zImage`
followed by the exact Stage A DTB, with component offsets, sizes and hashes in
`APPENDED-DTB-MANIFEST.txt`.

The target also emits `uImage-stage-a.compile-only`, a legacy wrapper around
the exact appended-DTB payload. Its `0x8000` load and entry fields match the
observed stock kernel header and are checked with host U-Boot tools. The
wrapper is still **not authorized for hardware boot**: a safe TFTP staging
address, exact command sequence, thermal stop plan and data/recovery gates
must be reviewed separately. No boot script, network transfer or flash image
is generated.
