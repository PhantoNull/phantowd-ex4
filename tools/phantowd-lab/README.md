# PhantoWD offline lab toolkit

`phantowd-lab` is a host-only, read-only research tool. It validates local
copies of the legacy WD My Cloud EX4 update, logical-mtd3 and logical-rescue
formats and replays passive captures of the internal front-controller protocol.

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
phantowd-lab inspect-gpt-image FILE
phantowd-lab inspect-ext-partition IMAGE-FILE GPT-PARTITION-NUMBER
phantowd-lab inventory-rootfs [--summary] DIRECTORY
phantowd-lab scan-storage-refs EXTRACTED-ROOT
phantowd-lab inspect-storage-inventory FILE
phantowd-lab plan-storage-inventory FILE
phantowd-lab catalog-mcu
phantowd-lab decode-mcu "fa 23 00 00 00 00 fb"
phantowd-lab replay-mcu [--format raw|hex] FILE
```

Artifact inspectors return exit status `0` when all currently understood
structure and XOR checks pass, `2` when a parsed artifact fails validation,
and `1` for usage, I/O, or structural errors. Results are JSON.

`inspect-mtd3` accepts the packed logical object containing the 2 KiB header
and SquashFS. It does not accept or interpret a physical NAND dump and makes no
claim about OOB, ECC, eraseblocks, or restoration.

`inspect-rescue` accepts only a regular-file logical rescue object and always
redacts the two per-device MAC fields in its JSON result. The report includes
only presence/validity booleans. For `valid`, both fields must satisfy this
tool's conservative policy: six colon-separated hexadecimal octets, three NUL
padding bytes, distinct values and unicast/nonzero addresses. This is a
PhantoWD parser gate, not a claim that every stock-device rescue record uses
this exact encoding. Its 2 KiB header schema comes from static GPL-binary
analysis and still needs corroboration from an exact-device logical rescue
read; it is not a rescue writer or restore procedure.

`inspect-gpt-image` inspects only bounded GPT metadata in a caller-supplied
regular image file. It checks the protective MBR, primary and backup headers,
header and partition-array CRCs, matching copies, partition bounds and
overlaps. It emits a path-free JSON report with disk and partition identities
replaced by deterministic SHA-256 fingerprints. A `valid-gpt` result means
only that the generic structures passed these checks; `wd_compatibility`
remains `unqualified`. This is not a WD layout detector or a disk-health,
filesystem, RAID, or migration check. It never opens a block device, repairs
metadata, assembles an array, mounts a filesystem, or writes the image. Exit
status is `0` for a structurally valid GPT and `2` for parsed damaged or
unsupported input; usage, I/O, and file-open errors return `1`.

`inspect-ext-partition` first requires a structurally valid GPT, then reads
only the standard 1024-byte ext-family superblock at byte offset 1024 within
the selected GPT partition. It reports bounded geometry, feature masks,
clean-unmount/journal-recovery flags and a redacted filesystem-UUID fingerprint
when present. Its `ext-superblock-candidate` status only means that selected
fields are structurally plausible; it does not distinguish ext2/3/4, validate
the superblock checksum, inspect other filesystem metadata or file contents,
or establish integrity, WD compatibility or mount safety. Exit status is `0`
for a plausible superblock, `2` for absent/damaged/unsupported metadata and
`1` for usage, I/O or file-open errors. Like the GPT command, it never opens a
block device, mounts, or writes the input image.

`inventory-rootfs` walks an already extracted directory without following
symlinks. It hashes regular files and records deterministic paths, sizes,
scripts and ELF loader dependencies. Its output is an evidence manifest, not a
complete package-manager SBOM: host extraction can lose SquashFS ownership,
device-node, xattr and mode information, and version/license attribution still
needs separate corroboration. Keep manifests of proprietary or
identity-bearing inputs in ignored private evidence storage.

`scan-storage-refs` separately searches an already extracted filesystem for a
fixed set of legacy disk, volume, share, and NFS path literals. It reads only
regular files up to 32 MiB, including binary files, and never follows symlinks
or opens special files. Reports contain relative file paths and recognized
tokens/counts, never source lines. Scanned bytes, empty files and skipped
entries are counted to make coverage limits visible. This is a literal-search
aid—not a complete code/data-flow analysis, disk-layout detector, or proof
that any path is active.
Keep reports of vendor extractions in ignored private evidence storage.

`inspect-storage-inventory` validates a project-owned, versioned JSON fixture
schema (currently version 1). It is not a WD XML parser and does not claim the
synthetic schema matches an undocumented vendor format. It checks that disk,
partition, and volume identifiers are unique and cross-referenced, and refuses
ambiguous logical volume numbers or stable UUIDs. A report derives an opaque
SHA-256 fingerprint from the filesystem UUID and optional md-array UUID; bay,
`/dev/sdX`, serial, WWN, PARTUUID and input-local IDs are not returned. The
historical `HD_*` path is emitted only as a compatibility hint derived from
the logical volume number, never as an identity or mount instruction. Input is
one UTF-8 JSON value up to 1 MiB; duplicate object keys and unknown fields are
rejected. This command reads only that regular file and never probes, assembles,
mounts or modifies storage. Parsed-but-invalid input exits 2; malformed or
unsupported input and I/O errors exit 1.

Minimal synthetic example (all identifiers are invented):

```json
{
  "format": "phantowd-storage-inventory",
  "schema_version": 1,
  "disks": [{
    "id": "disk-a", "wwn": "sample-wwn-a", "serial": "sample-serial-a",
    "bay": 1, "device": "/dev/sda"
  }],
  "partitions": [{
    "id": "partition-a", "disk_id": "disk-a", "number": 2,
    "partuuid": "sample-partuuid-a"
  }],
  "volumes": [{
    "id": "volume-a", "logical_volume_number": 1,
    "filesystem_uuid": "sample-filesystem-uuid-a",
    "filesystem_type": "ext4", "member_partition_ids": ["partition-a"]
  }]
}
```

The v1 schema validates an inventory supplied by a caller; it does not detect
hardware, establish filesystem health, prove a WD layout is supported, or
authorize an import. Do not treat the fingerprint as an authenticity check.

`plan-storage-inventory` consumes a version-1
`phantowd-storage-assessment` JSON envelope containing a synthetic inventory
and a `legacy_volume_metadata_state` fixture assertion. Accepted states are
`not_collected`, `absent`, `malformed`, and `present_unqualified`; these are
test inputs, not observations parsed from WD metadata. The command classifies
the supplied evidence as `candidate`, `ambiguous`, `damaged`, or
`unsupported`. `candidate` means only that the synthetic inventory is
internally consistent while legacy metadata was not asserted absent or
malformed. It does not imply a known or supported EX4 layout. Every result is
explicitly non-executable, includes an empty operation list, and redacts disk,
partition, filesystem, and array identifiers. Exit status is `0` only for a
synthetic candidate, `2` for parsed but non-candidate evidence, and `1` for
malformed/oversized input or I/O/usage errors. It reads only the supplied
regular file; it never probes hardware, assembles arrays, mounts, or modifies
storage.

Example assessment envelope (the nested manifest uses the synthetic v1 schema
shown above):

```json
{
  "format": "phantowd-storage-assessment",
  "schema_version": 1,
  "legacy_volume_metadata_state": "not_collected",
  "inventory": {
    "format": "phantowd-storage-inventory",
    "schema_version": 1,
    "disks": [{ "id": "disk-a", "wwn": "sample-wwn-a", "serial": "sample-serial-a", "bay": 1, "device": "/dev/sda" }],
    "partitions": [{ "id": "partition-a", "disk_id": "disk-a", "number": 2, "partuuid": "sample-partuuid-a" }],
    "volumes": [{ "id": "volume-a", "logical_volume_number": 1, "filesystem_uuid": "sample-filesystem-uuid-a", "filesystem_type": "ext4", "member_partition_ids": ["partition-a"] }]
  }
}
```

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
