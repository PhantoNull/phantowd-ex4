# PhantoWD offline lab toolkit

`phantowd-lab` is a host-only research tool with no device or installation
path. It validates local copies of the legacy WD My Cloud EX4 update,
logical-mtd3 and logical-rescue formats, prepares unsigned release metadata
from explicit regular payload files, verifies signed release metadata,
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

The passive MCU decoder accepts only the researched 7/13/15-byte envelopes.
Unsupported lengths return the observed length without retaining or encoding
raw bytes; supported-length diagnostics contain at most 30 hex characters.
Checksum status remains explicitly unknown. This is a host-only research
boundary, not a qualified controller driver or permission to transmit commands.

## Commands

```text
phantowd-lab build-release-manifest --artifacts DIR --public-key FILE --release-version VERSION --channel stable|beta|nightly --model ID --revision ID --source-commit SHA --buildroot-version VERSION --kernel-version VERSION --minimum-installer VERSION --artifact NAME:ROLE [--revision ID ...] [--artifact NAME:ROLE ...]
phantowd-lab inspect-github-release --tag VERSION --public-key FILE --model ID --revision ID --channel stable|beta|nightly [--current-version VERSION [--require-upgrade]] [--installer-version VERSION]
phantowd-lab inspect-release --manifest FILE --signature FILE --public-key FILE --artifacts DIR --model ID --revision ID --channel stable|beta|nightly [--current-version VERSION [--require-upgrade]] [--installer-version VERSION]
phantowd-lab plan-install --manifest FILE --signature FILE --public-key FILE --artifacts DIR --model ID --revision ID --channel stable|beta|nightly --installer-version VERSION [--current-version VERSION]
phantowd-lab inspect-update FILE
phantowd-lab inspect-mtd3 FILE
phantowd-lab inspect-rescue FILE
phantowd-lab inspect-gpt-image FILE
phantowd-lab inspect-dos-primary-image FILE
phantowd-lab inspect-storage-image DISK-IMAGE-FILE
phantowd-lab inspect-storage-image-set DISK-IMAGE-1 [DISK-IMAGE-2 [DISK-IMAGE-3 [DISK-IMAGE-4]]]
phantowd-lab inspect-md-v1.2-image-set DISK-IMAGE-1 DISK-IMAGE-2 [DISK-IMAGE-3 [DISK-IMAGE-4]]
phantowd-lab inspect-md-v0.90-image-set DISK-IMAGE-1 DISK-IMAGE-2 [DISK-IMAGE-3 [DISK-IMAGE-4]]
phantowd-lab inspect-ext-partition IMAGE-FILE GPT-PARTITION-NUMBER
phantowd-lab inspect-md-v1.2-partition IMAGE-FILE GPT-PARTITION-NUMBER
phantowd-lab inspect-md-v1.0-partition IMAGE-FILE GPT-PARTITION-NUMBER
phantowd-lab inspect-md-v1.0-component COMPONENT-IMAGE-FILE
phantowd-lab inspect-md-v1.0-component-set COMPONENT-IMAGE-1 COMPONENT-IMAGE-2 [COMPONENT-IMAGE-3 [COMPONENT-IMAGE-4]]
phantowd-lab inspect-md-v0.90-component COMPONENT-IMAGE-FILE
phantowd-lab inspect-md-v0.90-partition DISK-IMAGE-FILE GPT-PARTITION-NUMBER
phantowd-lab inventory-rootfs [--summary] DIRECTORY
phantowd-lab inspect-runtime-closure DIRECTORY IMAGE-RELATIVE-ELF
phantowd-lab inspect-nfs-runtime DIRECTORY
phantowd-lab scan-storage-refs EXTRACTED-ROOT
phantowd-lab inspect-storage-inventory FILE
phantowd-lab plan-storage-inventory FILE
phantowd-lab catalog-mcu
phantowd-lab decode-mcu "fa 23 00 00 00 00 fb"
phantowd-lab replay-mcu [--format raw|hex] FILE
```

`inspect-dos-primary-image` reads one 512-byte sector from a regular whole-disk
image and reports only the four primary entries, preserving slot numbers. The
logical sector size must be independently known to be 512 bytes. Extended,
protective/hybrid and known translated-overlay types refuse the entire table;
invalid flags/extents and overlap return no partial partitions. Boot code,
disk signatures, CHS, nested labels, filesystems and data are not interpreted.
An empty signed table does not prove an unused disk. Exit 0 means geometry was
observed, 2 damaged/unsupported input, 1 usage/I/O failure; WD compatibility,
health, identity, import and migration remain unqualified. Firmware stays GPT-only.
Layout reference: [Linux primary-entry declarations](https://github.com/torvalds/linux/blob/v6.6/include/linux/msdos_partition.h).

`build-release-manifest` emits **unsigned** schema1 JSON on stdout. It accepts
only a raw 32-byte public key, not a private key. Repeat `--artifact NAME:ROLE`
and `--revision ID` for explicit lists (at most16 each); payload filenames must
be flat, unique and safe. Revisions/names are sorted for reproducible bytes;
the public-key fingerprint, payload sizes and SHA-256 values are measured.
The existing manifest validators and size+1 bounded reader are reused. The
whole set's 1 GiB/member and 2 GiB/combined limits, plus the 64 KiB encoded
manifest limit, are checked before hashing. Source/target/version declarations
remain caller input, not provenance or hardware qualification. Payloads are
point-in-time observations, not retained immutable staging. A future approved
signing process must independently qualify provenance/staging and sign the exact
bytes. Private release keys must never enter ordinary PR jobs.

Exit `0` means an unsigned candidate was prepared, **not** a verified release or
permission to install. Invalid inputs/source observations return `1` without
metadata output. Output-write failures may leave a partial stream; discard it.
The command writes no file, payload, image or device and publishes no release.

Artifact inspectors return exit status `0` when all currently understood
structure and XOR checks pass, `2` when a parsed artifact fails validation,
and `1` for usage, I/O, or structural errors. Results are JSON.

`inspect-nfs-runtime` merges the dependency graphs of `rpcbind`, `rpc.mountd`,
`exportfs`, `rpc.nfsd`, `rpc.statd` and `sm-notify` from one extracted inventory.
Shared objects/aliases are counted once; the whole union is bounded by256
objects,1024 bindings and64 MiB. Missing or unsupported entries yield no partial
object set. Exit 0 means static resolution only,2 an incomplete/refused candidate,
and1 argument/inventory I/O failure. Runtime qualification and execution remain
false. Kernel NFSD/NLM, helper invocation, NSM state/recovery, NSS/configuration,
retained bytes, complete ABI and actual protocol/service behavior need separate
qualification. This command does not execute files, mount filesystems or start NFS.

`inspect-runtime-closure` reuses the extracted-tree inventory to derive a
**research-only** ARM32 little-endian ELF dependency candidate. The entry is a
canonical image-relative path, for example `usr/sbin/smbd`. It records hashes,
sizes and required aliases for the interpreter and recursive `DT_NEEDED`
objects. Symlink text is resolved inside the inventoried image; host targets
are never followed. Per-object literal `RUNPATH` precedes `/lib` and `/usr/lib`
and is not inherited by children. An entirely empty RUNPATH is ignored;
empty components of a nonempty list, RPATH, tokens, loader modifiers, conflicting
libraries and unresolved evidence are refused. See [loader search semantics](https://man7.org/linux/man-pages/man8/ld.so.8.html)
and [glibc's empty-path handling](https://github.com/bminor/glibc/blob/glibc-2.41/elf/dl-load.c).

The inventory also records observed processor-specific ELF `header_flags`
(including an observed zero). Every selected ARM object must have this evidence,
declare EABI version 5 and not declare the hardware floating-point procedure-call
ABI or BE-8 code. Both explicit soft-float and an implied base procedure-call ABI
are admitted, following [ARM's ELF header specification](https://github.com/ARM-software/abi-aa/blob/main/aaelf32/aaelf32.rst#elf-header).
Older inventory objects without this field are unknown, not implicitly supported.
These are header prerequisites only: ARM build attributes/instructions, symbol
versions and complete ABI compatibility remain unqualified.

For ARM files, the inventory separately reports `arm_attributes`: `absent`,
`unobserved`, `observed`, `invalid` or `unsupported`. The bounded
[Addenda32](https://github.com/ARM-software/abi-aa/blob/main/addenda32/addenda32.rst#representing-build-attributes-in-elf-files)
observer supports one public `aeabi` file scope, at most 64 KiB, 128 encoded
attributes/vendor subsections and 1,024-byte strings. Explicit integer zero is
retained; NTBS values use lossless `text_hex` without their terminating NUL.
Private vendor payloads remain opaque. Conflicting declarations, malformed
lengths/ULEB128, unsupported scopes/versions or exceeded budgets yield no
partial attribute roster. Missing attributes never become invented defaults.
This records declarations only: no instruction disassembly, linker inheritance,
CPU/extension classification, compatibility exception or execution grant.
`RuntimeClosure` retains its separate dependency/header-only contract; it does
not turn these observations into a complete ABI gate.

An optional read-only GNU target-readelf oracle runs against an existing trusted
Buildroot output, without executing target ELF or rebuilding an image:

```sh
cd tools/phantowd-lab
PHANTOWD_ARM_ATTRIBUTES_ORACLE_OUTPUT=/path/to/buildroot-output \
  go test -run '^TestARMAttributesTargetReadelfOracle$' -v ./rootfsinventory
go test -run '^$' -fuzz '^FuzzARMAttributesNeverExposePartialObservation$' \
  -fuzztime=50000x -parallel=2 -timeout=120s ./rootfsinventory
```

The current target oracle agrees on 1,444 CPU-name/architecture/ARM/Thumb values
across 361 attributed objects; the Go API has no attribute section. This is not
a comparison of every tag. The current `libatomic` declares v7/Thumb-2 and has
IFUNC variants: declarations alone must not be treated as proof that all code
executes on ARMv5, or that the library is broken. Dispatch/kernel-helper and
actual target execution require separate qualification.

The graph is capped at 256 objects, 1,024 bindings, 4,096 dependency edges and
64 MiB of selected regular-file bytes; source inventory retains its existing
250,000-entry limit and scans/hashes the whole extracted tree, not just the
candidate. Failure returns no partial object roster. Exit `0` means only that
this restricted graph resolved; `2` means refusal and `1` means usage/I/O error.
`runtime_qualified` and `execution_authorized` are always false. This does not
emulate loader caches, environment, hardware-capability directories, symbol/load
order, NSS or `dlopen`, or qualify ABI compatibility, trusted ownership,
configuration, writable state or privileges. It mounts/copies/executes nothing
and is not an approved service-root manifest or installer.

A separate [disposable ARMv5 loader differential](../../support/QEMU-FAST-TESTS.md#fixed-samba-elf-loader-differential)
compares candidate hashes, aliases and the dependency roster with the actual
public Buildroot loader, without starting Samba. It is not part of this CLI's
authority and does not qualify dynamic modules, state or privileges.

`inspect-release` checks a version-1 JSON manifest signed over its exact bytes
with a detached raw 64-byte Ed25519 signature. The caller supplies a raw
32-byte public key, the requested model/revision, and a directory containing
the named payload files. The requested channel is explicit too, so a valid
nightly signature cannot be mistaken for a stable-channel match. It rejects
duplicate/unknown/non-exact JSON fields, missing/null fields, wrong object/list
shapes, invalid UTF-8/surrogate repair, unsupported schema values, non-exact hardware
revision matches, unsafe artifact names, symlink/non-regular payloads, and
size or SHA-256 mismatches. The key ID is the
SHA-256 fingerprint of the supplied public key. Artifact reads happen only
after the signature, key ID, schema, exact model/revision, and requested
channel pass. Each file is capped at 1 GiB and the signed bundle at 2 GiB.
The fixed schema structure is checked before Go's case-insensitive struct
decoding: `Model_ID` is not `model_id`, including inside signed input. Canonical
decoded key names may use valid JSON escaping. Hashing consumes at most the
signed payload size plus one detection byte, even if the opened file grows;
changed opened size, short/long reads and observed metadata drift fail closed.
The report covers bytes read during that check only; a future device updater
must verify again immediately before installation. Exit status is `0` only
when the signature, metadata, target, and every artifact pass; `2` means a parsed
release is invalid for that key/target, a requested prerequisite refuses it,
or one or more payloads fail; `1` is
reserved for usage, input, or structural errors.

Both release-inspection commands optionally accept `--current-version` with the
installed `vMAJOR.MINOR.PATCH` version. When supplied, a verified report adds an
`update_policy` assessment that checks strict SemVer precedence and marks only a
strictly newer release as monotonic. This is an advisory host-side comparison:
the installed version is caller-supplied, no anti-rollback state is persisted,
and the result never authorizes installation. A same-version release or
downgrade is reported as not monotonic but does not change the release-integrity
exit status.

Add `--require-upgrade` to require a strictly newer signed release **before**
payload reads/downloads or temporary payload staging. This opt-in mode requires
a valid `--current-version`; missing/malformed syntax returns exit `1` before
opening CLI input files or making HTTP requests. Signature/schema/exact-target/
channel, GitHub signed-tag and optional minimum-installer checks still precede
the comparison. An equal/older version returns exit `2`, with
`upgrade_prerequisite` metadata-only evidence and `artifacts_checked: false`.
A newer version must still pass all payload size/hash checks. The separate
`update_policy` keeps its existing full-verification meaning; without the new
flag, existing advisory behavior and exit status are unchanged.

This avoids unnecessary host downloads; it is not device attestation, durable
anti-rollback protection, a rollback exception or installation permission.

Both commands also accept optional `--installer-version`. After signed metadata
and target checks, `installer_policy` compares that caller-supplied version
against the authenticated `minimum_installer`. Equal or newer versions pass;
older versions return exit `2` before any payload I/O or temporary payload
staging. Invalid version syntax returns exit `1` (before HTTP in the GitHub
reader). Omitting the option keeps the existing integrity-only behavior and
does not emit an installer assessment. Compatibility of this prerequisite
does not imply payload validity, installation permission or device readiness.

`inspect-github-release` is a host-side bridge for the planned public GitHub
distribution path. It requests one exact version tag from the PhantoWD EX4
repository (it does not follow a mutable `latest` pointer), requires the API to
report a published immutable release, and checks that the stable/non-stable
release flag is consistent with the requested channel. Asset requests start
only after the [API metadata boundary](githubrelease/README.md) accepts
unique, exact decoded consumed-field names, required non-null typed flags and
asset records. Case aliases, duplicate fields and missing `draft`/`prerelease`
observations cannot acquire published-release status. Additional GitHub fields
remain supported; they are not treated as signed application metadata. It fetches
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

Downloads handle both direct asset responses and redirects. Opaque signed query
parameters are accepted only on HTTPS `release-assets.githubusercontent.com`
with the default/443 port. API asset URLs from metadata remain exact and
query-free; foreign hosts, userinfo, fragments and HTTP CDN redirects are
refused. The existing redirect limit and caller redirect policy still apply.
Transport errors do not echo signed URLs or query credentials. Their underlying
causes remain available for `errors.Is`/`errors.As`, not public logging.
Local HTTP/TLS fixtures exercise complete signature/hash verification through
redirects, authentication-before-payload, tampering refusal and failed-download
staging cleanup. This does not qualify a real PhantoWD release or an installer.

The public release is the distribution location, not the trust anchor. The
caller still supplies a raw public key, so this host command cannot prove that
the caller chose PhantoWD's genuine key. A future device updater must use a
public key pinned in a trusted bootstrap/update component, persistently enforce
anti-rollback state, re-verify staged bytes immediately before install, and
have a tested recovery path. GitHub immutable releases prevent edits to a
published tag and its attached assets, but do not replace PhantoWD's signature
or device-side rollback policy. See GitHub's documentation on
[immutable releases](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases)
and [release asset downloads](https://docs.github.com/en/rest/releases/assets).

This is an offline host-side verifier, not the device updater: the caller must
obtain the public key through a separately trusted channel. Its result always
sets `installation_authorized` and `hardware_qualified` to false. The optional
version comparison does not establish persistent anti-rollback enforcement.
The tool does not establish key provisioning/rotation, release expiry, HIL
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

Static final-firmware analysis also identifies an opaque 64-byte per-unit
header field labelled "key" by the stock merger, populated from serial-related
input. This does not establish cryptographic semantics. The inspector does not
decode or expose that slot. Synthetic success/refusal/error tests check JSON
and formatted-report redaction plus unchanged input bytes; differing slot
contents produce identical public reports. No real per-unit material is used.
Header/payload reader failures return fixed messages without retaining the raw
reader error or its unwrap chain. Checksum observation must consume the full
declared range: early EOF is an I/O error even when omitted zero bytes preserve
XOR. A complete read ending in ordinary EOF remains supported; an additional
read error is not a completion certificate. The exact-read checks also cover the
shared logical-image checksum path; raw-error redaction above is rescue-specific.
Neither guarantees that files cannot change during inspection. The existing
bounded `FuzzInspect` campaign additionally tests
coherent rescue images with generated data up to64KiB plus a missing zero-word tail.
These tests do not qualify an inner rescue payload or authorize restoration;
see the [board recovery research](../../board/wd/ex4/NAND-RECOVERY-RESEARCH.md).

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
existing GPT, ext-superblock, MD v1.2, MD v1.0, and MD 0.90 readers to a regular
whole-disk image. The filesystem and RAID observations remain independent per
partition: the command does not reconcile members, infer a WD layout, examine
file data, or establish health, integrity, compatibility, or mount safety.
Every parser remains bounded to its relevant metadata. Invalid or unsupported
GPT returns `2` without partition observations; a valid GPT returns `0` even
when individual generic superblocks are absent, unsupported, or damaged, so
inspect those per-format statuses in the JSON. It never opens a block device,
mounts, assembles, or writes the image.

`inspect-storage-image-set` accepts one to four whole-disk regular image files
and correlates only their bounded generic metadata. It reports duplicate GPT
disk GUID, PARTUUID and ext filesystem UUID fingerprints within the supplied
set; per-partition declaration/signature summaries; and the existing MD v1.2,
MD v1.0, and MD 0.90 image-set comparisons. If any GPT is invalid or
unsupported, it withholds all cross-image identity and array comparisons instead of presenting
a partial set as complete. Mixed ext/MD signatures, duplicated identities,
conflicting/divergent arrays, or incomplete/unsupported probes require manual
review. `metadata-observed` means only that the supplied generic observations
passed these limited checks; `wd_compatibility` remains `unqualified` and
`migration_authorized` is always false. The tool cannot prove all four bays
were supplied, determine health or filesystem integrity, or authorize
assembly, mounting, import, or migration. It emits no input paths or unique
disk GUIDs, PARTUUIDs, filesystem UUIDs, or raw array IDs; generic GPT type
GUIDs may appear as declarations only. It never opens a block device or
modifies an image. An ext-family candidate not marked clean, recording errors
or unknown state flags, or indicating journal/orphan recovery is held as
`incomplete`; the tool never runs repair or recovery. Set schema **5** retains
`ext_filesystem_state` and independent `ext_needs_orphan_recovery` summaries;
these review findings return exit `2`, even when the raw clean bit is set.
Each partition now includes `ext_space_counters`: recorded ext free/reserved
values or null when absent, invalid, unsupported or conflicting with an MD
candidate. Values remain scoped to the input ordinal and partition number,
never summed across cloned images, components or arrays. A duplicate identity
still requires review. These are not live allocator or migration capacity;
the nested `migration_capacity_qualified` flag always remains false.
Inputs are not locked or snapshotted, so callers must use
stable offline copies and prevent concurrent modification during inspection.

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

`inspect-md-v1.0-partition` first requires a structurally valid GPT and then
reads one generic Linux MD metadata 1.0 component superblock at its standard
end-of-component location plus the bounded member-role array. It checks the v1
checksum and component bounds, and returns only redacted identity fingerprints.
Metadata 1.0 is an end-of-device format, unlike v1.2's fixed offset near the
start. A candidate does not prove that other members agree, that the array is
complete or healthy, or that the EX4 supports the layout. It does not assemble,
mount, write, or authorize migration. Sets whose feature map is nonzero remain
`incomplete` because the corresponding optional semantics are not qualified.
Exit status is `0` for one plausible
component, `2` for absent/damaged/unsupported metadata and `1` for usage, I/O
or file-open errors.

`inspect-md-v1.0-component` performs the same bounded read on a caller-supplied
regular-file component image, treating the complete file as one MD component.
Use it for extracted partition images or other offline component copies. It
does not accept block devices, assemble arrays, mount filesystems or modify the
input. `inspect-md-v1.0-component-set` compares two to four such standalone
component files. It omits GPT partition numbers because these inputs are
already-extracted components; ordinal input indexes are not physical identities.
Exit `0` requires exactly one identified array, checksummed candidates with no
unqualified components, and complete active-role coverage. Other parsed sets
return `2` with `review-required`; usage/I/O errors return `1`. A successful
comparison still says only `wd_compatibility=unqualified` and does not establish
data synchronization, health, import safety or recovery. The command never
opens block devices, assembles arrays, mounts, or writes input images.

`support/test-qemu-md-v10.ps1` exercises the firmware's internal bounded MD
v1.0 reader and the offline GPT-partition/whole-disk/component-set comparators
against ARMv5 mdadm-authored metadata. The QEMU guest writes only to partition
1 of two 32 MiB disk images held in tmpfs; after stopping the array, the
firmware parser reads each member through a generation-bound O_RDONLY block
descriptor. The host independently verifies both GPT-disk reports, extracts
the exact partition ranges into temporary regular files, and checks the
standalone component-set report plus unchanged hashes. This does not qualify
any WD/EX4 layout; the firmware parser is not connected to the storage broker
or a product endpoint.

`inspect-md-v0.90-image-set` accepts two to four whole-disk regular image
files, requires valid generic GPT on each, and groups plausible little-endian
MD 0.90 component superblocks by redacted array fingerprint. It compares only
array level and RAID-disk count, event counters, member numbers, and assigned
RAID-slot coverage. It reports each component's `nr_disks` value but does not
require these values to match: Linux explicitly treats `nr_disks` as
non-constant MD 0.90 metadata. A `raid-slot` is only an assigned role; the
comparator reports the raw `this_disk.state` value plus Linux 3.2-defined
`faulty`, `active`, `sync`, `removed`, and `write-mostly` flag names. These are
stored descriptor metadata, not live measurements. It returns all 27 stored
descriptors per component, exposing descriptor index, member number, role,
state and recognized state flags while omitting kernel major/minor numbers
and reserved words. Across images, it compares member number, role, and state
by descriptor index; a mismatch is reported as a stored-metadata conflict.
Kernel major/minor numbers are deliberately excluded. Agreement is not proof
of a live or valid device, and this comparison does not reconcile the table
with `this_disk`. The component report schema is version 3, the nested
image-set report schema is version 4, and the outer whole-disk CLI envelope
remains version 1.
The descriptor layout and flag definitions follow the
[upstream Linux v3.2 MD header](https://github.com/torvalds/linux/blob/v3.2/include/linux/raid/md_p.h);
the relationship between the array table and `this_disk` follows its
[version-matched MD implementation](https://github.com/torvalds/linux/blob/v3.2/drivers/md/md.c).
`metadata-consistent` is a narrow metadata result -- not evidence of data
synchronization, health, WD compatibility, migration safety, or safe assembly.
Missing roles, duplicate member
numbers/assigned slots, conflicting geometry, and differing event counters
are non-success statuses. Unidentified array IDs are counted but never
grouped. Paths and raw IDs are omitted; inputs are identified by ordinal. The
command uses regular files only and does not open block devices, assemble
arrays, mount filesystems, or modify images.

`inspect-ext-partition` first requires a structurally valid GPT, then reads
only the standard 1024-byte ext-family superblock at byte offset 1024 within
the selected GPT partition. It reports bounded geometry, feature masks,
clean-unmount/journal/orphan-recovery flags and a redacted filesystem-UUID fingerprint
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

Ext report schema **4** retains the raw clean bit independently from errors,
unknown state flags and recovery indicators. `needs_orphan_recovery` observes
the orphan-processing state bit, a nonzero legacy orphan-list head, or the
orphan-present feature; it does not follow or validate an orphan chain/file.
Journal recovery remains a separate flag. A single-partition exit `0` is still
only structural recognition, not a safe-mount verdict. The whole-image envelope
remains schema **2**, with nested ext report **4**; the image-set assessment is
schema **5**. Flag definitions follow the
[upstream ext superblock documentation](https://www.kernel.org/doc/html/latest/filesystems/ext4/super.html)
and recovery indicators are cross-checked against
[Linux v6.18 ext4](https://github.com/torvalds/linux/blob/v6.18/fs/ext4/super.c).

`space_counters` records free/reserved blocks and bytes from the superblock,
including dynamic-revision 64-bit counters. `unreserved_free_bytes` is the
recorded free count minus the recorded reservation, clamped at zero. A full
filesystem explicitly reports zero; absent, damaged or unsupported metadata
reports `space_counters: null`. Inconsistent reserved counters are damaged,
not a capacity estimate. These are offline counters, not live allocator,
quota, recovery, freshness or migration-space proof:
`migration_capacity_qualified` always remains false. No filesystem is mounted.

`feature_review` names declared bits using the
[Linux v6.18 definitions](https://github.com/torvalds/linux/blob/v6.18/fs/ext4/ext4.h#L2043-L2098),
retains unclassified bits separately for all three feature families and gives
fixed review reasons for selected constraints such as encryption, journal-device
declarations, MMP, inline data, casefold, quotas, bigalloc and verity. Separate
nonzero external-journal UUID/device references also require review; only their
presence is returned. These flags
declare what may be present; no file contents, keys or external journal are read.
Unvalidated metadata returns null. The image-set `ext_feature_review` keeps a
candidate `incomplete` when review is required. A known flag or `required:false`
does not establish PhantoWD support, WD compatibility, integrity or mount safety.

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
member counts, reports the stored `this_disk.state` and Linux 3.2 flag names,
and returns the 27-entry array-wide descriptor table as a redacted stored
snapshot. Major/minor device-node values and reserved words are omitted. A
descriptor's values and flags are not live device-health measurements or
proof that an array is complete. It fingerprints the array UUID. It supports
little-endian version 0.90 only; it does not inspect optional bitmap data, other v0 minor
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
receive envelopes. Handler classification is length-specific:

| Envelope | Supported classification |
| --- | --- |
| 7 bytes | Three-byte catalog prefixes, except the version handler; thermistor prefix `03 08` with sensor byte `01` or `02`; status families `40`, `41`, `42` by their first byte only |
| 13 bytes | Retained as an unknown envelope: the stock RTC branch bypasses selector validation, so matching its first bytes is not enough to establish a catalog identity |
| 15 bytes | Only the `MCUVer` handler, with its three-byte catalog prefix |

`dispatch_key` always retains raw bytes 1 through 3, including bytes which are
payload in the variable-prefix families; it is not a universal fixed selector.
`known` means a supported handler classification, not integrity, device state
or command completion. The fourth template byte remains catalog metadata.
The thermistor sensor byte selects the stock SATA/main destinations, but the
decoder deliberately does not convert the raw lookup input into a temperature:
physical calibration, valid range and units remain unqualified. It does not
reproduce the legacy receiver's unchecked lookup or other side effects.

The decoder reports
every new `0xfa` as a fresh frame start, abandoning any incomplete prefix and
counting it as malformed; input chunk boundaries do not change that result.
Standalone decoding rejects interior start markers without assigning a selector
or button event, while retaining only the existing bounded raw diagnostic.
This follows the final firmware's `up_read_daemon` restart branch at0x88f8–0x8908;
`librs232.so`'s `RS232_Read` at0x904–0x924 directly wraps `read` without an escape
decoder. This is static host-receiver evidence, not an observed hardware trace.
These are ELF virtual addresses, not device-register addresses. Input SHA-256:
`up_read_daemon` `66da626b7a96922a6c3875f5e956cd488281a13225e7c27ce8d6756193f84d18`;
`librs232.so` `de585e83da528c704f1d37524ccc7cd0e76684cb7863223f61857176c9b29794`.
The stock ACK handler writes a generic XMLDB flag, and the sender tests that
flag; recognizing an ACK selector does not confirm a particular command.

The decoder still reports
checksums as `unknown-not-validated`; complete payload interpretation,
ACK correlation, and thermal fail-safe behavior remain
research questions. Synthetic replay is not proof that active hardware control
is safe.

## Tests

### M10.2 installer-version preflight task contract

The host release inspectors may accept an explicit `--installer-version` using
the existing bounded SemVer rules. Compare it with `minimum_installer` only
after the detached signature, schema, exact target and channel pass (and, for
GitHub, the signed version matches the immutable tag). Equal or newer installer
versions satisfy this prerequisite; a prerelease below a stable minimum does
not. An incompatible installer refuses before any payload read/download or
temporary payload staging. Invalid supplied syntax is a usage/input error
before network activity. Omitting the option preserves integrity-only behavior
and must not imply that installer compatibility was checked.

The version is caller-supplied, not an observation of a device. The result is a
host prerequisite assessment, never installation permission, physical
qualification, persistent anti-rollback or target recovery. No target code,
signing scheme, manifest schema, trust roots or device operation changes.
Acceptance includes local CLI refusal before unavailable payloads, real
synthetic HTTP request counts, signature/target-first ordering, version
boundaries and the complete host-tool vet/unit/race suite. No QEMU build is
required for this host-only change.

From the repository root with Go 1.24 or newer:

```powershell
.\support\test-lab-tools.ps1
```

Tests use generated redistributable fixtures. No WD firmware, device dump,
network connection, NAS address, or credential is required.
The container suite also performs four fixed-count fuzz campaigns for the
vendor update parser, passive MCU stream decoder, receive diagnostic bounds
and synthetic storage-inventory/dry-run boundary; arbitrary inventory input
must never become executable. The lightweight host CI runs the first three
with 10,000 executions each and two workers, without building a firmware image.
