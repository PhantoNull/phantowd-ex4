# Buildroot configurations

`phantowd_qemu_armv5_defconfig` is the non-flashable development baseline. It
uses QEMU's ARM926/VersatilePB machine to exercise an ARMv5 userspace and a
modern kernel without pretending to emulate the EX4 board.

The QEMU configuration is deliberately named `qemu`, not `ex4`. An eventual
EX4 defconfig will only be added after a model-specific device tree, peripheral
bring-up, a non-persistent boot path, and recovery have been validated.

`phantowd_ex4_stage_a_defconfig` is a compile-only exception with an explicit
stage name, not a production EX4 defconfig. It creates a storage-disabled,
network-disabled built-in initramfs for static inspection and later bounded
serial-only RAM bring-up. It is not flashable or hardware-validated.

Use one defconfig per supported model and hardware revision when they differ.
Do not make a single image probe several incompatible NAS models during an
update. CI may use a build matrix, but every output must have an unambiguous
model identifier and compatibility metadata.
