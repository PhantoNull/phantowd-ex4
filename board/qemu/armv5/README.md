# ARMv5 QEMU development target

This target boots an ARM926EJ-S userspace on QEMU's VersatilePB machine. It is
useful for validating the cross-toolchain, early userspace, service lifecycle,
resource budgets, and future update logic on the same ARM instruction baseline
as the current EX4 discovery data.

It is not an EX4 emulator. QEMU does not model the EX4 NAND layout, SATA
topology, watchdog, thermal sensors, fan controller, display, LEDs, buttons, or
the secondary-UART management controller. A successful QEMU boot is therefore
necessary evidence for the software layer, but never authorization to flash a
real NAS.

Build on Windows with Docker Desktop:

```powershell
.\support\build-qemu.ps1
```

The wrapper verifies the signed Buildroot release metadata, both pinned source
hashes, builds in a persistent Docker volume, boots the result, and copies only
the reviewable runtime artifacts to `artifacts/qemu-armv5/`.
