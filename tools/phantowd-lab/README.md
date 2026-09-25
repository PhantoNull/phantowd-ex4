# PhantoWD offline lab toolkit

`phantowd-lab` is a host-only research tool with no device or installation
path. It validates local copies of the legacy WD My Cloud EX4 update,
logical-mtd3 and logical-rescue formats, verifies signed release metadata,
optionally inspects a public GitHub release, and replays passive captures of
the internal front-controller protocol.

It intentionally provides **no** extraction, image construction, flash access,
serial-port access, command transmission, firmware installation, or device
discovery. The GitHub command performs anonymous HTTPS GETs and temporarily
stages only the release payloads it is checking; it deletes that temporary
directory before returning. Other artifact inspectors accept regular files only; symlinks,
block/character devices and pipes are rejected. Rootfs inventory accepts an
already extracted directory, never follows its symlinks and opens only regular
children. Captures larger than 16 MiB are rejected where applicable.

## Commands

```text
phantowd-lab inspect-github-release --tag VERSION --public-key FILE --model ID --revision ID --channel stable|beta|nightly
phantowd-lab inspect-release --manifest FILE --signature FILE --public-key FILE --artifacts DIR --model ID --revision ID --channel stable|beta|nightly
phantowd-lab inspect-update FILE
phantowd-lab inspect-mtd3 FILE
phantowd-lab inspect-rescue FILE
phantowd-lab inspect-gpt-image FILE
phantowd-lab inspect-storage-image DISK-IMAGE-FILE
phantowd-lab inspect-md-v1.2-image-set DISK-IMAGE-1 DISK-IMAGE-2 [DISK-IMAGE-3 [DISK-IMAGE-4]]
phantowd-lab inspect-ext-partition IMAGE-FILE GPT-PARTITION-NUMBER
phantowd-lab inspect-md-v1.2-partition IMAGE-FILE GPT-PARTITION-NUMBER
phantowd-lab inspect-md-v0.90-component COMPONENT-IMAGE-FILE
phantowd-lab inspect-md-v0.90-partition DISK-IMAGE-FILE GPT-PARTITION-NUMBER
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

`inspect-release` checks a version-1 JSON manifest signed over its exact bytes
with a detached raw 64-byte Ed25519 signature. The caller supplies a raw
32-byte public key, the requested model/revision, and a directory containing
the named payload files. The requested channel is explicit too, so a valid
nightly signature cannot be mistaken for a stable-channel match. It rejects
duplicate/unknown JSON fields, unsupported schema values, non-exact hardware
revision matches, unsafe artifact names, symlink/non-regular payloads, and
size or SHA-256 mismatches. The key ID is the
SHA-256 fingerprint of the supplied public key. Artifact reads happen only
after the signature, key ID, schema, exact model/revision, and requested
channel pass. Each file is capped at 1 GiB and the signed bundle at 2 GiB.
The report covers bytes read during that check only; a future device updater
must verify again immediately before installation. Exit status is `0` only
when the signature, metadata, target, and every artifact pass; `2` means a parsed
release is invalid for that key/target or one or more payloads fail; `1` is
reserved for usage, input, or structural errors.

`inspect-github-release` is a host-side bridge for the planned public GitHub
distribution path. It requests one exact version tag from the PhantoWD EX4
repository (it does not follow a mutable `latest` pointer), requires the API to
report a published immutable release, and checks that the stable/non-stable
release flag is consistent with the requested channel. It downloads only
`manifest.json` and `manifest.sig` first. The exact-byte signature, schema,
model, board revision, channel and signed version-to-tag match must pass before
the tool downloads any firmware payload. It then downloads exactly the assets
listed in the signed manifest, rejects missing/unlisted release assets and
size mismatches, hashes the downloaded bytes locally, and removes the private
temporary staging directory. GitHub API metadata and transport hashes are not
used as a substitute for the detached Ed25519 signature or local SHA-256
checks. GitHub anonymous API access is currently limited to 60 requests per
hour per source IP, so this manual command does not poll or retry a `latest`
endpoint. See GitHub's [REST API rate-limit documentation](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api).

The public release is the distribution location, not the trust anchor. The
caller still supplies a raw public key, so this host command cannot prove that
the caller chose PhantoWD's genuine key. A future device updater must use a
public key pinned in a trusted bootstrap/update component, keep its own
anti-rollback state, re-verify the staged bytes immediately before install,
and have a tested recovery path. GitHub immutable releases prevent edits to a
published tag and its attached assets, but do not replace PhantoWD's signature
or device-side rollback policy. See GitHub's documentation on
[immutable releases](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases)
and [release asset downloads](https://docs.github.com/en/rest/releases/assets).

This is an offline host-side verifier, not the device updater: the caller must
obtain the public key through a separately trusted channel. Its result always
sets `installation_authorized` and `hardware_qualified` to false. It does not
establish key provisioning/rotation, anti-rollback, release expiry, HIL
qualification, NAND layout, a safe slot, or an installation/recovery path.
The signature protects the exact manifest bytes; artifacts are bound by the
signed size and SHA-256 entries. No files are extracted, modified, installed,
or sent to a device.

The signed JSON object uses these fields:

```json
{
  "format": "phantowd-release-manifest",
  "schema_version": 1,
  "product": "phantowd",
  "release_version": "v0.1.0",
  "channel": "nightly",
  "model_id": "wd-my-cloud-ex4",
  "hardware_revisions": ["board-r1"],
  "source_commit": "<40-or-64-lowercase-hex-characters>",
  "buildroot_version": "2025.02.18",
  "kernel_version": "6.18.53",
  "minimum_installer": "v0.1.0",
  "signing_key_id": "sha256:<public-key-fingerprint>",
  "artifacts": [
    {"name": "release.swu", "role": "swupdate-bundle", "size_bytes": 1234, "sha256": "<64-lowercase-hex-characters>"}
  ]
}
```

The example is schema documentation only; its revision and payload are not
qualified artifacts. Hardware revision identifiers must be explicit tokens,
never wildcards. For current development, no revision row has been qualified
for a public PhantoWD EX4 release.

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

`inspect-storage-image` produces one read-only JSON snapshot by applying the
existing GPT, ext-superblock, MD v1.2, and MD 0.90 readers to a regular whole-
disk image. The filesystem and RAID observations remain independent per
partition: the command does not reconcile members, infer a WD layout, examine
file data, or establish health, integrity, compatibility, or mount safety.
Every parser remains bounded to its relevant metadata. Invalid or unsupported
GPT returns `2` without partition observations; a valid GPT returns `0` even
when individual generic superblocks are absent, unsupported, or damaged, so
inspect those per-format statuses in the JSON. It never opens a block device,
mounts, assembles, or writes the image.

`inspect-md-v1.2-image-set` accepts two to four whole-disk regular image files,
requires valid generic GPT on each, and groups candidate MD v1.2 component
superblocks by redacted array fingerprint. It compares selected array fields,
event counters, member identities/numbers, and active RAID-role coverage. A
`metadata-consistent` result means only that those parsed metadata checks agree
and all active roles are represented in the supplied images; it does not mean
the array is synchronized, healthy, safe to assemble, or compatible with WD.
Missing roles, duplicate roles/identities, conflicting fields, and differing
event counters receive distinct non-success statuses. Input paths are omitted
from the report and inputs are identified by ordinal only. MD 0.90 candidates
are counted but not compared by this command. No block device is opened, no
array is assembled, no filesystem is mounted, and no image is changed. This
tool does not authorize an import or migration.

`inspect-ext-partition` first requires a structurally valid GPT, then reads
only the standard 1024-byte ext-family superblock at byte offset 1024 within
the selected GPT partition. It reports bounded geometry, feature masks,
clean-unmount/journal-recovery flags and a redacted filesystem-UUID fingerprint
when present. Its `ext-superblock-candidate` status only means that selected
fields are structurally plausible; it does not distinguish ext2/3/4, validate
other filesystem metadata checksums, inspect file contents, or establish
overall filesystem integrity, WD compatibility or mount safety. When the
metadata-checksum feature is set, it verifies the ext superblock's CRC32C and
rejects unknown checksum algorithms; without that feature it reports the
checksum as not advertised or unknown. Exit status is `0`
for a plausible superblock, `2` for absent/damaged/unsupported metadata and
`1` for usage, I/O or file-open errors. Like the GPT command, it never opens a
block device, mounts, or writes the input image.

`inspect-md-v1.2-partition` first requires a structurally valid GPT, then reads
only one Linux native MD metadata v1.2 component superblock at its
partition-relative location and the bounded variable-length member-role array.
It checks the v1 checksum, basic partition/data bounds, and redacts array and
member UUIDs to deterministic fingerprints. Its candidate status says nothing
about other members, array-wide event consistency, RAID health, filesystem
integrity, WD compatibility or safe assembly. It does not inspect v1.0/v1.1,
legacy 0.90, vendor-specific RAID metadata, filesystem data, or disks directly.
No array is assembled, mounted, or modified. Exit status is `0` only for a
plausible v1.2 component superblock, `2` for absent/damaged/unsupported
metadata, and `1` for usage, I/O or file-open errors.

`inspect-md-v0.90-component` accepts a regular file containing one caller-
supplied Linux MD component device (usually a partition image), not a whole
disk image to be partitioned automatically. It reads exactly the standard
4096-byte v0.90 superblock at the end-of-device offset defined by Linux's
64-KiB reservation/alignment rule, validates its legacy checksum and bounded
member counts, and fingerprints the array UUID. It supports little-endian
version 0.90 only; it does not inspect optional bitmap data, other v0 minor
versions, v1.x or vendor metadata. A candidate establishes neither member
agreement nor EX4 compatibility or assembly safety. The command never opens a
block device, assembles an array, mounts, or modifies the image. Exit status is
`0` for one plausible component, `2` for absent/damaged/unsupported metadata,
and `1` for usage, I/O or file-open errors.

`inspect-md-v0.90-partition` is the whole-disk-image counterpart: it first
validates generic GPT, selects one partition, then applies the same bounded
little-endian MD 0.90 component check to that partition's byte range. It does
not infer a WD table from a valid GPT, check filesystem metadata, compare RAID
members, or authorize assembly/mounting. It never opens a block device or
modifies the image. Exit status is `0` for a plausible component, `2` for
absent/damaged/unsupported metadata or a missing partition, and `1` for usage,
I/O or file-open errors.

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
