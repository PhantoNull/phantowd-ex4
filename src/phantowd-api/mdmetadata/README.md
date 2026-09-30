# Read-only MD metadata observation

`mdmetadata` parses one generic Linux MD metadata 1.0 superblock from a
caller-selected 512-byte-sector partition range. It is observation only: a
candidate is not an assembled or healthy array, an approved WD layout, a
filesystem-integrity result, or permission to migrate or mount.

`InspectPartition` is a bounded pure reader used by host tests. The Linux-only
`InspectBlock` entry point additionally requires a caller-owned O_RDONLY whole-
disk block descriptor and a nonzero observed major/minor/diskseq tuple. It
checks descriptor type/access mode, `BLKGETSIZE64`, `BLKSSZGET`, `BLKGETDISKSEQ`
and major/minor before and after parsing. The caller remains responsible for
complete trusted discovery, GPT validation, candidate eligibility and the
final inventory recheck. The parser never opens a path, invokes `mdadm`, or
assembles, mounts, imports, repairs or writes storage.

Only the standard MD 1.0 end-of-component location is read: one 256-byte fixed
header and a role array bounded to 4 KiB. The checksum, partition bounds,
component data range and role index are checked. Raw array/member UUIDs never
enter the observation; domain-separated fingerprints are private and explicitly
not authenticators or persistent identities. Only 512-byte logical sectors are
accepted. Other metadata versions, feature semantics and WD-specific layouts
remain unsupported/unqualified.

`CompareComponents` correlates a bounded caller-supplied set of parser results
from at most four disk indexes and 128 partition indexes per disk. It rejects
duplicate/out-of-range locations and parser results rebound to another
partition; only checksummed candidates with canonical array and member
fingerprints enter comparison. It classifies generic metadata as consistent,
incomplete, divergent by event counter, conflicting in array-level fields, or
ambiguous from repeated member identity/number/active role. Every active RAID
role must be present for `metadata-consistent`; the array fields and component
data size must agree across members. It requires no device access, and all
comparison fields are excluded from JSON. As with the single-member parser,
that status is not health, synchronization, WD compatibility, or permission to
assemble/mount/import.

The implementation is currently exercised in the fixed ARMv5 QEMU fixture,
not by the storage broker or a product endpoint. QEMU `mdadm` creates metadata
on two synthetic GPT partitions in tmpfs. The firmware's internal coordinator
then performs complete trusted discovery, correlates the full GPT set, selects
only Linux-RAID-declared partitions, parses them through generation-bound
O_RDONLY descriptors and rechecks storage, mounts and swap. The guest array is
stopped before parsing. Its pure component comparer checks the same two active
RAID1 roles; the independent offline host parser reads the same regular files
and confirms their hashes did not change. No physical device or NAS is
involved. This remains a QEMU-only test path, not a broker operation or product
observation API.
