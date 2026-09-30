<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors -->

# WD My Cloud EX4 storage compatibility

**No WD EX4 disk layout is currently qualified for automatic import or
migration by PhantoWD.** A parser recognizing a generic filesystem or RAID
superblock is not evidence that the complete WD layout is understood, healthy,
or safe to assemble. Do not attach valuable disks to an experimental build or
use this table as a recovery procedure.

This matrix separates static observations from synthetic parser coverage and
product support. Status applies to the listed combination; it must not be
generalized to another firmware, partition scheme, RAID mode, or device.

## Legacy layout evidence and current disposition

| Candidate | Evidence in WD 2.13.108 | PhantoWD recognition evidence | Migration status |
| --- | --- | --- | --- |
| One-disk `standard` data volume | Static installer logic selects `standard` for one healthy disk; REST documentation uses the different term `JBOD`. The discrepancy is unresolved. | Generic GPT, ext and MD metadata readers; no verified EX4 data-disk image or complete layout. | **Not qualified.** Do not infer that `standard` and JBOD are interchangeable. |
| Multi-disk `linear` / JBOD | The firmware contains mode mapping and user-interface references; the exact runtime mapping and on-disk member layout are not established by a real sample. | No WD-specific layout recognizer. | **Not qualified.** |
| Data RAID0, RAID1, RAID5 or RAID10 | These modes occur in the static firmware mode mapper. Installer paths indicate Linux MD metadata 1.0 for data-array creation. The live member list, partition scheme, offsets, array UUIDs, filesystem and per-mode recovery behavior are not established. | Generic MD 1.0 parser, checksummed component comparison, and an mdadm-authored ARMv5 QEMU fixture on synthetic GPT partitions. The parser is not connected to product discovery. | **Not qualified.** Synthetic MD agreement is not WD compatibility, array health, synchronization, or permission to assemble. |
| RAID6 | A static UUID/mode mapping exists, but the reviewed RAID initialization script has no complete RAID6 branch. | No WD RAID6 layout recognizer. | **Unsupported by current evidence.** |
| Legacy root mirror and swap | Static installation logic creates an MD 0.90 RAID1 root mirror using ext3 and a swap partition. These are system-installation artifacts, not evidence for the user-data array. | Generic offline MD 0.90 and filesystem metadata readers; no supported product importer. | **Not a data-volume migration target.** Never classify a root mirror as user data from its filesystem signature alone. |
| `/DataVolume` ext4 | Static installation scripts create an ext4 data filesystem at `/DataVolume`; example partition numbers and sector ranges are comments, not an observed live layout. | Generic ext-family metadata inspection. An unclean, errored, or journal-recovery-needed ext candidate is held for review; no repair is performed. | **Not qualified.** Filesystem recognition alone does not establish array membership, ownership, ACLs, or safe mounting. |
| GPT partition tables | No verified claim that every supported WD data layout uses GPT. | Strict generic GPT validation and private GPT/sysfs correlation are tested on generated images and QEMU disks. | **Not qualified as a WD layout.** |
| DOS/MBR partition tables | Exact use by each WD data layout is unknown. | Offline tools can inspect generic DOS structures, but the current firmware identity observation is GPT-only. | **Not qualified.** No stable identity is inferred from MBR in the firmware path. |
| Encrypted, LVM, NTFS/UFSD, or other optional layouts | Firmware flags and modules show some optional capabilities; a live encrypted/LVM data-volume sample and complete key/recovery contract are absent. UFSD is a commercial component in the stock image. | No product compatibility or migration path. | **Not qualified.** |
| iSCSI backing objects | The stock firmware includes iSCSI capability; no general supported backing-object format/import contract is established here. | No product target importer. | **Not qualified.** Existing LUNs must be treated as separate data that requires its own verified backup and migration plan. |

Static findings above come from analysis of WD My Cloud EX4 firmware
`2.13.108.0109.2022`. They describe code paths and configuration capabilities,
not a live NAS, a particular disk, or proof that those services were active.
The documented example partition geometry is not a device profile. The actual
runtime `DVC_MDS` member data, complete disk corpus, and bay-to-member mapping
remain unavailable.

## What parser results mean

- **Generic metadata observed**: bounded structures passed the specific
  parser's checks in the supplied synthetic or offline input.
- **WD layout recognized**: not currently implemented. It requires a
  versioned, sanitized corpus of real WD data-volume metadata with provenance
  and independently verified interpretation.
- **Migration qualified**: not currently achieved for any layout. It requires
  explicit compatibility policy, safe array/filesystem lifecycle, ownership
  and ACL mapping, interrupted-operation recovery, backups, and healthy
  expendable-media tests.

The host-only `phantowd-lab` image inspectors never open block devices. The
firmware exposes an explicit, manual GPT metadata observation; its MD v1.0
reader is currently exercised only by a disposable QEMU fixture and is not
connected to a product observation endpoint. Both paths are bounded and
read-only. Neither mounts, assembles, imports, repairs, or writes media. An
observation is not a health check. Unsupported or incomplete coverage must
remain visible and fail closed; the software must not silently fall back to an
empty directory or initialize a disk.

## Evidence required to change a status

Before any row can become supported, add sanitized independent samples covering
the exact partition scheme, partition geometry, member metadata, filesystem and
relevant version/feature flags. Record whether the sample is a whole disk,
partition, or extracted component and how its integrity was verified. Keep
proprietary firmware, raw user metadata, serials, credentials, and private
identity values out of the public repository. Use synthetic fixtures for
negative, duplicate, incomplete, reordered, degraded, and interrupted cases.

An advertised import combination additionally requires healthy disposable
media on exact EX4 hardware, bay-move and replacement tests, a verifiable data
backup, content/ownership/ACL comparison, and a demonstrated return/recovery
path. Never qualify it using the two production disks or the damaged spare as a
healthy-media substitute.
