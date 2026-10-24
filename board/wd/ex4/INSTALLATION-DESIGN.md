<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors -->

# EX4 installation layout review

**Status: review record; no production layout or writer is approved.**
[G8 option B](../../../ROADMAP.md#g8-qualifying-m10-while-preserving-the-only-ex4)
defers physical qualification until a sacrificial exact-model EX4 exists.
The only unit must be preserved. Host verification and logical previews can
continue; this record neither authorizes device operations nor closes M10.1.
Research artifacts remain compile-only/non-flashable and are not update images.

## Evidence boundary

| Evidence | What it supports | What it does not support |
| --- | --- | --- |
| [Stock NAND/recovery source analysis](NAND-RECOVERY-RESEARCH.md) | Specific reader, header, ECC-source and partition-parser observations | A physical image, exact bootloader parity, safe write path or demonstrated rescue |
| [EX4 board research](README.md) | Narrow historical diskless RAM observations and current disabled NAND | Persistent boot, installed storage/services or repeatable recovery |
| [Host release verifier](../../../tools/phantowd-lab/releaseverify/README.md) | Signed bytes, declared model/revision/channel/version and payload checks | Attested device identity, retained staging, payload-format compatibility or write authority |
| [Storage compatibility](../../../STORAGE-COMPATIBILITY.md) | Generic metadata observations and explicit unsupported/unknown cases | Qualified WD migration or permission to assemble/mount user disks |

The supplied GPL kernel's board table is fallback data, not an EX4 installation map.
Its driver invokes default partition parsers before that fallback. The selected
GPL configuration enables command-line partition parsing; its successful result
can supersede the C table. See the [source trace](NAND-RECOVERY-RESEARCH.md#board-defaults-are-not-a-qualified-partition-map).
This establishes source precedence, not the parameters actually supplied to a
distributed kernel. A missing or malformed declaration must not be interpreted
as permission to use whichever partition table happens to appear.

Future layout review must reconcile physical ranges, labels, enumeration,
boot parameters and both bootloader/kernel consumers. Partition number/order
alone is insufficient. Unknown, overlapping or conflicting ranges refuse a
plan; they do not trigger repartitioning or a fallback writer.

## Candidate layouts — no default selected

| Candidate | Potential benefit | Unresolved evidence before selection |
| --- | --- | --- |
| Retain stock boundaries | Limits the initial layout change | Kernel/ramdisk/rootfs updates are separate; atomic publication, old/new compatibility and an independently recoverable interrupted update are unproven. |
| Internal A/B system slots | Could preserve a previous system while preparing another | Fit after bad-block/reserve overhead, bootloader-readable slot selection, bounded attempts, rollback state and per-unit identity preservation must all be proven. Repartitioning is not assumed acceptable. |
| Dedicated external system medium | Could separate system writes from internal NAND | Exact persistent boot/recovery support, missing-media behavior, storage endurance and ownership require qualification. It must not silently take space or mandatory system state from user-data disks. |

RAM/TFTP research is a development route, not an installed product or an
implicit fourth production choice. Spare nominal capacity, an unused-looking
region or a successful QEMU boot does not select any candidate above.
Do not replace the bootloader or reuse a rescue/configuration region to make
a candidate fit. A bootloader change requires its own approved recovery design.

## Capacity admission to design, before implementation

Capacity is a per-profile and per-unit question, not just a host file length.
For each candidate, record and independently review:

1. Exact physical device/profile and consumer-compatible geometry, alignment,
   ECC/OOB and bad-block policy; distinguish nominal area from usable space.
2. Immutable kernel/ramdisk/rootfs bytes and their container/slot metadata.
   Determine whether the boot consumer expects a packed logical stream, UBI
   volume or another representation. These are not interchangeable raw images.
3. Initial and future bad-block reserves, boot metadata, recovery and previous
   system retention. A sample unit's good-block count is not a fleet minimum.
4. Persistent state, transaction/journal overhead, minimum free-space reserve
   and any old/new state copies required for rollback.
5. Peak temporary space and RAM: download, signature/hash verification,
   decompression, retained old/new payloads, active root filesystem, processes
   and kernel/page-cache use. An archive's compressed size is not peak RSS.

The required upper bound plus explicit recovery/metadata reserves must fit
the qualified usable capacity. Unknown values refuse admission; equality
without operating headroom is not a proposed budget. Round raw logical streams
to qualified erase geometry; UBI instead needs its actual logical-eraseblock
capacity and metadata/reserve accounting. Do not reuse one calculation for both.

The host verifier's parser/read limits (1 GiB per payload, 2 GiB per set) are
input bounds, **not EX4 RAM, flash or staging budgets**. QEMU image dimensions,
test timeouts and host build memory are likewise not physical release budgets.
M11 must supply measured EX4 resource limits before product qualification;
this record invents no capacity, performance or wear targets.

## Boot and trust contract to qualify

Stock XOR/CRC detects some corruption; it does not authenticate an update.
Adding signatures to the updater does not turn the legacy bootloader into
verified boot or protect against every privileged/physical replacement.

Before any target transaction, the design must identify:

- Bootstrap trust roots and their provisioning, authorized rotation/recovery,
  exact hardware compatibility and rollback/version policy.
- The exact bytes retained after verification, their physical representation
  and all boot consumers. A point-in-time pathname/hash check is not staging.
- A coherent kernel, initramfs/rootfs and state-version set; partial updates
  must not leave an arbitrary old/new combination eligible for normal boot.
- Boot-selection storage, durability ordering, bounded trial attempts and an
  independent recovery path when selection/state is torn or unreadable.
- Readiness criteria and who commits them. A running web page alone is not
  proof of correct storage identity, state recovery or enabled sharing policy.

Selection/fallback must not depend on writable state stored only in the new
system being trialed. Power loss at every publication boundary must retain a
known outcome or an independently demonstrated recovery route. No such physical
protocol has yet been qualified; the host preview therefore always refuses.

## State, data and identity separation

| Class | Required treatment |
| --- | --- |
| Immutable system | Versioned/coherent payload set; previous qualified system retained when the selected recovery design requires it |
| Product state | Explicit versioned store for configuration, account/volume identity, transaction evidence and update policy; bounded growth and compatibility review |
| Volatile runtime | Bounded logs, probe output, caches and temporary files; no uncontrolled repeated NAND writes |
| User data | Separate from installation/staging; no automatic format, partition change, MD assembly, filesystem repair or permission rewrite |
| Per-unit identity | Preserve privately, validate representation and retain association to the original unit; never publish or clone another unit's identity |

State location must allow defined boot/recovery with user disks absent or
replaced. User disks must not become an undocumented requirement for the
management/recovery system. Large application data and iSCSI backing files are
not firmware-state payloads. Bay and transient kernel paths are not volume IDs.

Before selection, define write frequency, flash wear assumptions, bounded log/
history retention, atomic state publication, free-space failure and uncertain
transaction handling. A filesystem's journal or successful fsync in QEMU is
not proof of power-loss durability on the EX4's physical medium.

System rollback does not undo user-data writes or a state-schema migration.
The old/new state compatibility policy must be explicit before committing a
trial; do not reset configuration, recreate LUNs or loosen access policy to
make an older system start. Recovery of an uncertain intent requires separately
qualified behavior, not silent replay.

The stock rescue header contains per-unit fields; the slot labelled "key"
does not establish cryptographic semantics. Its encoding/body association is
unqualified. Preserve opaque identity material privately rather than normalizing
it into an invented schema. U-Boot environment, both NIC identities, device
identity and product-owned enrollment/update state need separate review; this
is not a claim that all of them reside in the same region.

## Recovery and qualification record still required

M7.6b must reconcile the rescue producer, both distinct readers, body boundaries
and boot selection. The bit28 source finding is not a recovery trigger to use;
`mtd_check` is not diagnostic. A backup without a demonstrated restore does not
establish an unbrick route. No current operation may test these on the only EX4.

| Decision/evidence | Present disposition |
| --- | --- |
| Qualification route | Owner selected G8 B; physical qualification deferred |
| Production layout | Unselected; candidate comparison above is design input only |
| Exact partition/boot-consumer agreement | Static source evidence only; complete profile not qualified |
| Slot/staging/state/wear budget | Required; no physical admission or invented target |
| Trust provisioning and rollback/state policy | Requires explicit design and review; host signature tests are insufficient |
| Rescue body and restoration | Unresolved; M7.6b remains open |
| Power-loss and per-unit identity preservation | Requires sacrificial exact-model drills after G8 prerequisites |
| Installer execution | Absent; host verify-only preview remains refused |

Next offline work may refine these contracts and test signed-input/refusal or
synthetic state transitions. A writer must wait for a separately approved
written design and the required recovery evidence. This document is neither
that approval nor an operational installation/recovery procedure.
