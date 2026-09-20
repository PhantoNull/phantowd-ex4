# PhantoWD offline lab toolkit

`phantowd-lab` is a host-only, read-only research tool. It validates local
copies of the legacy WD My Cloud EX4 update, logical-mtd3 and logical-rescue
formats, validates legacy U-Boot image headers and payload CRCs, and replays
passive captures of the internal front-controller protocol.

It intentionally provides **no** extraction, image construction, flash access,
serial-port access, command transmission, firmware installation, or device
discovery. Artifact inspectors accept regular files only; symlinks,
block/character devices and pipes are rejected. Rootfs inventory accepts an
already extracted directory, never follows its symlinks and opens only regular
children. Captures larger than 16 MiB are rejected where applicable.

## Commands

```text
phantowd-lab inspect-update FILE
phantowd-lab inspect-mtd3 FILE
phantowd-lab inspect-rescue FILE
phantowd-lab inspect-uimage FILE
phantowd-lab inventory-rootfs [--summary] DIRECTORY
phantowd-lab catalog-mcu
phantowd-lab decode-mcu "fa 23 00 00 00 00 fb"
phantowd-lab replay-mcu [--format raw|hex] FILE
```

The artifact inspectors return exit status `0` when all currently understood
structure and integrity checks pass, `2` when a parsed artifact fails
validation, and `1` for usage, I/O, or structural errors. Results are JSON.

`inspect-uimage` validates the standard 64-byte legacy U-Boot header, its
header and payload CRC32 values, declared size, load address, entry point,
operating system, architecture, image type and compression. It rejects
truncated payloads and reports unauthenticated trailing data separately. It
exposes no image-construction or boot-command path.

`inspect-mtd3` accepts the packed logical object containing the 2 KiB header
and SquashFS. It does not accept or interpret a physical NAND dump and makes no
claim about OOB, ECC, eraseblocks, or restoration.

`inspect-rescue` accepts only a regular-file logical rescue object and always
redacts the two per-device MAC fields in its JSON result. Its 2 KiB header
schema comes from static GPL-binary analysis and is labelled as needing
corroboration from an exact-device read; it is not a rescue writer or restore
procedure.

`inventory-rootfs` walks an already extracted directory without following
symlinks. It hashes regular files and records deterministic paths, sizes,
scripts and ELF loader dependencies. Its output is an evidence manifest, not a
complete package-manager SBOM: host extraction can lose SquashFS ownership,
device-node, xattr and mode information, and version/license attribution still
needs separate corroboration. Keep manifests of proprietary or
identity-bearing inputs in ignored private evidence storage.

`--summary` omits paths and file hashes while retaining the tree digest,
aggregate counts, architectures, interpreters and required-library frequencies.

The MCU decoder recognizes the statically recovered 7-, 13-, and 15-byte
receive envelopes and classifies the first three selector bytes. It reports
checksums as `unknown-not-validated`; the fourth selector-template byte,
variable payloads, ACK correlation, and thermal fail-safe behavior remain
research questions. Synthetic replay is not proof that active hardware control
is safe.

## Tests

From the repository root with Go 1.24 or newer:

```powershell
.\support\test-lab-tools.ps1
```

Tests use generated redistributable fixtures. No WD firmware, device dump,
network connection, NAS address, or credential is required.
