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
target for the serial-only RAM bring-up. Its kernel configuration
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

The output remains labelled compile-only and non-flashable. One exact-device,
diskless RAM transfer and boot has proven this specific wrapper, appended DTB,
embedded initramfs, serial marker and halt path. It does not prove pinmux or
thermal behavior beyond that short trial, fan control, storage, NAND, recovery
or the safety of repeating the test.

Buildroot embeds the generated `rootfs.cpio` in `zImage`; the separate CPIO is
retained only for static inspection. Linux's appended-DTB and ATAG-compatibility
options are enabled for this old-bootloader research path, and the verifier
also emits `zImage-with-appended-dtb.compile-only`: exactly the raw `zImage`
followed by the exact Stage A DTB, with component offsets, sizes and hashes in
`APPENDED-DTB-MANIFEST.txt`.

The target also emits `uImage-stage-a.compile-only`, a legacy wrapper around
the exact appended-DTB payload. Its `0x8000` load and entry fields match the
observed stock kernel header and are checked with host U-Boot tools. The
wrapper is still a research artifact: no installer, flash image or automatic
boot script is generated. The one-time physical result does not authorize
unreviewed boot attempts or production use.

## Stage B Ethernet-enumeration research target

`configs/phantowd_ex4_stage_b_defconfig` retains Stage A's minimal BusyBox and
storage/flash exclusions, then enables the Linux network core, `mv643xx_eth`,
MDIO and one candidate PHY mapping for Ethernet 0. Its init only checks that
`eth0` and an MDIO device appear, records the observed MAC over serial, and
halts after 20 seconds. It does not bring up the interface, obtain an IP
address, send packets or run a network service. The PHY mapping and factory
MAC identity remain hardware hypotheses.

Build and audit locally with `.\support\build-ex4-stage-b.ps1`. This verifies
the pinned source archives without first rebuilding the full QEMU target and
checks free space on Docker Desktop's default Windows data drive. The resulting
artifact is ignored by Git and explicitly non-flashable. One diskless
exact-device RAM boot reached the Stage B `eth0`/MDIO enumeration marker and
halted; it did not raise a link, identify a factory MAC or prove cooling and
recovery. Do not attach user-data disks.

The first local offline build completed with a 3,870,646-byte legacy uImage.
An independent parser verified both header and payload CRCs; the final DTB
retains an all-zero placeholder MAC address, so factory identity and the
candidate PHY mapping must be observed on hardware before any network use.
The same PR head passed clean compile-only CI before the narrow physical
trial. The observed MAC was a placeholder, not factory identity.

## Stage B2 dual-Ethernet link-observation research target

`configs/phantowd_ex4_stage_b2_defconfig` is a **separate** non-flashable
candidate. It retains Stage B's disabled NAND, SATA, MTD and other unqualified
peripherals, then enables the second Ethernet controller and candidate MDIO
PHY at address 1. A dedicated BusyBox fragment adds only `ifconfig`; the
fixed `/init` raises each interface briefly, reads its sysfs MAC, carrier and
operational state over serial, lowers both interfaces, and halts. Linux's
`MV643XX_ETH` driver requires the IPv4 core, but the kernel omits IPv6, IP
autoconfiguration and NFS, while userspace has no IP/DHCP/bridge/service
tools. Stage B2 therefore never assigns an address or starts a service.
Raising a port does start electrical link negotiation; this is not a passive
probe.

Build and audit with `.\support\build-ex4-stage-b2.ps1` on Windows/Docker.
Exact-head CI and two independent builds produced byte-identical uImages.
Separate, reviewed diskless RAM trials with one rear jack cabled at a time
enumerated both NICs and two MDIO devices. The left jack mapped to `eth0` /
candidate PHY 0; the right jack mapped to `eth1` / candidate PHY 1. Each
interface finished with carrier up at 1 Gbit/s while the other remained down.
The short observations recorded two left-port and one right-port down/up
transitions, so sustained link stability remains unqualified. Both interfaces
retained the known placeholder MAC. The fixed init lowered both interfaces
and halted automatically. Factory identity, cooling, recovery and repeatability
remain unverified. These results do not authorize installation or use with
disks.

## Stage B3 combined network and sensor observation

Stage B3 is a separate, compile-only RAM research target that groups three
checks into one short run: it checks whether Linux receives two distinct,
non-placeholder MACs from temporary U-Boot variables; both interfaces are
raised together and sampled at two-second intervals; and the SoC's internal
thermal zone is read over serial. It keeps IP autoconfiguration, IPv6, packet
sockets, network services, storage, MTD, NAND, SATA and the fan controller
unavailable. The thermal sensor is tripless and observational; it is not a
thermal safety system.

For an exact-device trial, use that EX4's stock `mac1`/`mac2` values as U-Boot
`ethaddr`/`eth1addr`, read them back, and never run `saveenv`. The initramfs
reports placeholder MACs as a warning so the independent link/sensor
observations can continue, but still rejects duplicate addresses before
raising interfaces. It configures no IP and starts no network service. Both
HDDs must remain removed. This test does not qualify MAC handoff when a
placeholder warning appears, fan control, sustained link stability, storage,
recovery or installation.

Build and audit with `.\support\build-ex4-stage-b3.ps1` on Windows/Docker.
The output remains explicitly non-flashable and is not authorized for a
physical boot until its exact artifact and a bounded run procedure are reviewed.
