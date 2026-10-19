<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors -->

# NAND and recovery research

This is a static research record, **not an installation or restore procedure**.
NAND remains disabled in the EX4 research device trees. No writer, recovery
image, production layout or rollback mechanism is qualified.

## Stock Linux ECC path

The supplied WD GPL 2.12.127 kernel archive contains the following evidence.
Its bundled kernel uImage and the final 2.13.108 kernel uImage both hash to
`7201bcfee26c251fec0dfe51c5e6de2945aeaf2f9cf0c7b3ef588f93bb5c194d`.
This strengthens the source comparison; it does not independently reproduce
that kernel or prove the included `.config` produced it.

| Source inside `linux-3.2.40/` | Observation |
| --- | --- |
| `.config`, lines 888–904 | Orion NAND enabled; RS ECC, BCH and SMC byte ordering disabled |
| `drivers/mtd/nand/orion_nand.c`, lines 24–60, 545, 636–652 | Default is `NAND_ECC_SOFT`; the `nandEcc=` parser and Reed–Solomon override are inside the disabled RS configuration |
| `drivers/mtd/nand/nand_base.c`, lines 3374–3387 | Software ECC uses `nand_calculate_ecc` / `nand_correct_data`, a default 256-byte step and three ECC bytes per step |
| Same file, lines 76–85, 3286–3300 | The default 64-byte OOB layout places 24 ECC bytes at offsets 40–63 and declares offsets 2–39 free |
| Same file, lines 3462–3467 | Steps are page size divided by step size; total ECC bytes are steps times bytes per step |
| `drivers/mtd/nand/nand_ecc.c`, lines 356–405 | The SMC configuration changes the ECC byte order; it must not be silently substituted |

With the observed 2,048-byte pages and 64-byte OOB, this source/configuration
path implies eight 256-byte Hamming steps and 24 ECC bytes per page. These
are **source-derived parameters**, not an observed raw-page decode or proof
of U-Boot compatibility. They describe normal ECC-managed transfers, not raw
MTD operations that bypass that path. OOB bytes declared free are not permission
to discard them from an archive. Bad-block markers, scan-page policy and any existing
factory data require separate preservation.

The observed stock environment contains `nandEcc=1bit`. An environment value
is not automatically a Linux command-line argument. Even if passed to Linux,
this particular Orion parser is excluded by the supplied configuration.
Its meaning inside the bootloader is a separate unresolved implementation.
Do not enable RS/BCH or select a Linux 6.18 ECC profile from the presence of
supporting code alone.

### Reproducible input identities

The archive is available from the [WD GPL source distribution](https://downloads.wdc.com/gpl/WDMyCloud_EX4_GPL_v2.12.127_20181219.tar.gz).
The nested `kernel/linux-3.2.40.tar.gz` is 108,758,174 bytes, SHA-256
`bdd034a67b011a850ad4d4a2eb76e3c171f1e0a9442496318ad80bf127e93f9e`.
Member hashes below are over raw archive-member bytes, not line-normalized
terminal text. Inspection needs only archive reads; do not execute vendor
programs or extract a complete new tree for this check.

| Member under `linux-3.2.40/` | SHA-256 |
| --- | --- |
| `.config` | `f6a70192d44319e20b6efd5217316c1a277145268dab346e3fc761cccd678131` |
| `drivers/mtd/nand/orion_nand.c` | `78a69c66617b1e1aab38fcb47dd6d913e2b000338d0c22be1415e092e49a4173` |
| `drivers/mtd/nand/nand_base.c` | `563c1a7c407ba90627845d5470a4c954f61561d72bf3d6881ec8d13eecf38eef` |
| `drivers/mtd/nand/nand_ecc.c` | `8f04e40be8512ca6b3db8ef61f6e27354a17dd7eeddc4993008f2aff9907e252` |
| `arch/arm/plat-orion/mv_hal/gpp/mvGppRegs.h` | `ce5cf0bb2c4391a950ebbfae90b8b199499c7490039115f51ce5014e3c0ba3ec` |

## Rescue readers are not one format

The final `chk_image` is 9,923 bytes, SHA-256
`c8ef7fb5c21d9f51844f3a35e7ddd80d1873b204e805a865c5fc761b0804f600`.
Static ARM code and file-backed ELF literals distinguish these paths:

- Normal rootfs reconstruction removes its 2 KiB logical mtd3 header and
  verifies the payload XOR.
- If `/image.cfs` exists, the main routine follows that earlier branch before
  the register test described below. Otherwise it reads the word at
  `0xf1010108` and tests bit 28 (`0x10000000`): `0x91b4–0x91c0`, reader
  `0x9084–0x9114`. A set bit selects the mtd4 helper at `0x8eb0` through
  `0x9268–0x9278`. This is a **Linux userspace branch**, not an observed
  U-Boot rescue selector. `mvGppRegs.h`, line 106, calls offset `0x10108`
  the bank-zero blink-enable register; its use as a boot signal and its
  writer/lifetime remain unqualified. It is not an ordinary button read.
- That helper requests a 10 MiB bad-block/OOB-omitting mtd4 dump, then seeks
  to `0x501000` in the temporary file: `0x8ee4`, `0x8f24–0x8f30`, literal
  `0x8fcc`. It copies 1,024-byte reads, including a final short read, to
  `/usr/local/tmp/image.cfs`. The inspected path does not check the command,
  seek or write results and has no independent copy-length counter.

`0x501000` is **5 MiB + 4 KiB**, not 5 MiB + the known 2 KiB rescue header.
Only assuming a successful, exactly 10 MiB dump and successful seek would the
remaining file length be `0x4ff000`. This is not a guaranteed output size or
an assignment of the intervening components. Do not derive a rescue extractor
or writer by combining these offsets with a guessed payload layout.

The separate `rescue_fw` logical-header reader checks identity, length and XOR.
It must not be conflated with this fixed-offset `chk_image` fallback. Neither
reader proves the actual rescue boot flow or a working unbrick procedure.

## The header merger does not construct the rescue body

The final `upload_firmware`, SHA-256
`d616668b4544835d14d2105906851201d89c5c077dce7402a2684cfcb27ca3aa`,
contains a routine labelled "Merge rescue fw" at `0xd544`. Its static flow
reads 2 KiB from the supplied pathname, closes it, updates header fields, then
reopens that pathname and requests one 2 KiB write at offset zero. It does not
retain the original file object between those opens. Read/seek/write counts
and the final write-open result are not checked in this path.

| Header range | Statically observed update |
| --- | --- |
| `0x00–0x13`, `0x1c–0x2f` | Two fixed 20-byte MAC fields, not six-byte binary addresses (`0xd7e8–0xd818`) |
| `0x30` | Normalized model/color selector; only decimal 1 becomes 1 (`0xd71c–0xd734`, `0xd844–0xd84c`) |
| `0x31` | Normalized `hidden_encryption` flag, with a separate file-existence fallback (`0xd73c–0xd758`, `0xd884–0xd894`, `0xd9f4–0xda08`) |
| `0x100–0x13f` | A 64-byte per-unit field labelled "key", populated from an `SN` token or serial fallback (`0xd65c–0xd688`, `0xd874–0xd880`, `0xd950–0xd9f0`) |

That label does **not** establish a cryptographic key, encryption algorithm or
encrypted rescue body. The routine also regenerates an identity-bearing text
file and requests its copy to persistent configuration (`0xd8a4–0xd914`). It
is neither read-only nor a body-layout generator. No relationship between
these header updates and the fallback's `0x501000` offset is demonstrated.

The host inspector leaves that per-unit slot opaque. Synthetic tests cover
its absence from JSON, formatted reports and parser errors on valid and
rejected inputs, unchanged source bytes, and identical public reports for
four different slot contents. They do not qualify real-device encoding or
prove arbitrary data cannot be placed in otherwise public fields.

### Standalone rescue-input dispatch

The same final updater already receives a file at its dispatch entry `0xbe80`.
It loads that file through `0xbd44`, then classifies the returned bytes at
`0x9dc0`: the normal magic is compared at offset `0x30`, while the rescue magic
is compared at `0x32`; a rescue match returns type2. The rescue branch retains
the original pathname rather than using the normal-update branch's separate
configuration pointer.

| Static edge | Observed responsibility |
| --- | --- |
| `0xc0f8–0xc164`, then `0xc370` | Rescue-type prefix/checksum/selector checks before the dedicated file validator |
| `0xc39c -> 0xd2b4` | Validate the supplied rescue file; this is not construction of its body or qualification of that legacy validator's unchecked-I/O paths |
| `0xc424–0xc428 -> 0xdabc`, then `0xdb24–0xdb28 -> 0xd544` | Pass the same pathname to the legacy writer and its header merger |

The classifier's two12-byte magic literals and712 instruction/literal words
across these regions and two dispatch callers match the original file-backed
ELF load mappings. This is static GNU-report/ELF evidence, not target execution,
REA-native Evidence or a proof of every direct/indirect producer. It narrows the
boundary: this traced path consumes an already rescue-classified input; it does
not explain how that input's body was originally generated. Do not derive its
layout from the normal update container or the separate `0x501000` reader.
The actual rescue body producer, selector-register writer and stock bootloader
handoff remain unresolved; no extractor, writer or installer is added.

## `mtd_check` is not a diagnostic command

The final helper is 14,175 bytes, SHA-256
`bd82a129fdde832b14afd4958a31f9e60ebc6cac4a011a760c6cf80bf17c61b3`.
Its main routine selects UBIFS (`0x9108–0x9110`). A missing `/etc/mtab` match
for the configuration path, or return -1 from its repair/check helper, reaches
the formatter at `0x922c` (`0x9120–0x9158`). That mount-table lookup does not
attempt a mount or verify filesystem type. The repair/check helper is not a
complete structural XML validator.

The selected formatter requests unmount, UBI detach, config-partition erase,
optional formatting, reattach, volume creation and UBIFS mount. It ignores
the external-command results and returns zero after sync without verifying
the new mount (`0x92c4–0x9354`, `0x926c–0x9274`). That return is not a
verified success receipt. These are dangerous static paths, not commands to
run. Do not reuse this helper for migration, recovery or inspection.

The final ramdisk `etc/rc.sh`, SHA-256
`9017255849a372139f0262c8671714c2b3cc4b4be599c10c59d700278e13e48f`,
calls it in the USB-controller-detection failure branch when its retry marker
is absent (lines 60–66), **not unconditionally on every normal boot**. No
direct writer of the rescue-selection register was established in the traced
helper; indirect effects of its external programs remain unexamined. The
actual register writer and complete rescue boot selection are still unknown.

## Qualification sequence still required

| Gate | Required evidence before advancing |
| --- | --- |
| Offline layout | Reconcile rescue producers and both readers, identify the register writer and precedence, assign remaining header fields; test synthetic truncated/ambiguous inputs without executing vendor code |
| Capture design | Separate raw data+OOB archives from ECC-corrected packed streams; record exact chip/geometry, ECC implementation/ordering, correction status, bad-block locations/scan policy, acquisition tool/version/options and hashes; preserve per-unit identity privately |
| Independent review | Review source-derived parameters against the exact stock bootloader and a proposed Linux profile; do not infer parity from Linux readback alone |
| Dedicated EX4 drill | On sacrificial exact-model hardware only, demonstrate bootloader-readable restoration, stock rescue selection, identity preservation and interruption recovery; no important-data disks |
| Installation design | Only after those proofs select capacity/wear/state/rollback layout and signed transaction; a spare partition or valid SquashFS is insufficient |

QEMU VersatilePB does not emulate the EX4 NAND controller, bootloader ECC or
rescue selection. Parser/unit tests can reduce software uncertainty, but cannot
close these physical gates. See [board status](README.md),
[M7.6](../../../ROADMAP.md#m7-ex4-board-controller-and-thermal-qualification)
and [M10](../../../ROADMAP.md#m10-signed-installer-upgrades-and-recovery).
