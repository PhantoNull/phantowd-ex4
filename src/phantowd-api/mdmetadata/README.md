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

The implementation is currently exercised in the fixed ARMv5 QEMU fixture,
not by the storage broker or a product endpoint. QEMU `mdadm` creates metadata
on two synthetic GPT partitions in tmpfs; the firmware parser examines each
through generation-bound O_RDONLY descriptors, then the independent offline
host parser checks the same images. The guest array is stopped before parsing.
No physical device or NAS is involved.
