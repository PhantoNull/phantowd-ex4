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
mapper, modules and other optional buses. Mainline `MACH_KIRKWOOD` forces the
unused PCI core to remain compiled in, while the DTB explicitly disables the
PCIe controller and every other known non-console peripheral.

Build and statically verify it with:

```powershell
.\support\build-ex4-stage-a.ps1
```

The output is deliberately labelled compile-only. It does not prove U-Boot
load addresses, boot commands, pinmux, clocks, thermal behavior, halt behavior
or recovery, and must not be used on hardware before those gates are reviewed.
