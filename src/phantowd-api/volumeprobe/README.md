# Supervised descriptor metadata probing

The Linux `Inspect(ctx, source)` entry point runs the fixed firmware helper
`/usr/libexec/phantowd-volume-probe` on one already-selected read-only descriptor.
It is an internal observation primitive, not an HTTP API, device opener,
complete inventory, volume resolver or service activation capability.

## Contract

- One active invocation per process, without an unbounded wait queue. A second
  request receives `ErrBusy`; separate processes need broker-level coordination.
- Duplicate the supplied descriptor while protected against concurrent close;
  reject writable, O_PATH, directory and pipe descriptors before execution.
  Do not close the caller's file. The shared offset may change, so the caller
  must exclusively own its open-file description while probing.
- Fixed executable, no arguments, minimal environment (no inherited loader or
  debug settings), separate process group, eight-second context deadline and
  one-second pipe-wait limit. Cancellation kills the process group and waits
  for the helper to be reaped before releasing the slot. Kernel uninterruptible
  I/O can delay reaping: this is not a hard wall-clock guarantee or a sandbox.
- Both output streams have a 1024-byte retained-data limit, including `io.Copy`
  paths. Any stderr, unsuccessful exit, timeout or malformed response fails
  without returning identity. Underlying diagnostics are not echoed.
- Require every schema field, exact names/types, bounded UTF-8 JSON, no nulls,
  duplicates, unknown fields or trailing documents. All three authority flags
  must be present and false. Validate status/type/UUID relationships and check
  the reported source kind against the supplied descriptor.
- Compare device/inode/rdev/size/mode/mtime/ctime before and after a successful
  child. This catches some changes, not all concurrent writes or device swaps,
  and does not provide an atomic or continuously valid storage snapshot.

The helper is trusted, non-daemonizing firmware code installed in a directory
unwritable by untrusted users. This runner is not a supervisor for arbitrary or
hostile executables, independently escaping descendants, or privilege changes.
No new privileges, mount operation, device enumeration or source-path opening
is added. Result UUIDs are private and must not enter public diagnostics/logs.

## Verification and remaining integration

`ObserveSet(ctx, sources)` retains up to 32 supplied descriptors, probes them
sequentially under one process-wide slot, and rechecks every object before
returning a snapshot. Any failed input/probe/recheck discards the whole result.
The set has a 30-second context deadline, subject to the same kernel-I/O limit.
An explicitly empty set is valid; a nil collection is refused. There is no
device enumeration, automatic omission, weaker retry or mount operation.

`ObserveBlockSet(ctx, sources)` is the generation-bound variant for callers
that already opened read-only whole-disk descriptors and captured each object's
major/minor plus nonzero `diskseq` from trusted kernel observations. The caller
must establish that entries are whole disks rather than partitions; this
primitive checks for block descriptors but does not classify sysfs partitions.
It verifies `fstat()` reports a block device with that exact device number and
requires `BLKGETDISKSEQ` to return the expected sequence before probing and
again after the entire set. Invalid/reused expected generations, an ioctl
error, or any mismatch refuses the complete set. Repeated aliases for one
device are allowed only with the same device number and generation. Linux
defines `diskseq` as a unique, monotonically increasing number for a
block-device instance; see the
[block-device generation](https://github.com/torvalds/linux/blob/master/block/genhd.c),
[ioctl definition](https://github.com/torvalds/linux/blob/master/include/uapi/linux/fs.h)
and [kernel handler](https://github.com/torvalds/linux/blob/master/block/ioctl.c).
It is transient kernel-lifetime evidence, not persistent media identity. This
primitive does not reopen/revalidate the caller's pathname or rediscover the
inventory, and the caller must still establish completeness, eligibility,
unmounted state and stable topology. It is not mount authorization.
The set-level timeout, single-slot limit, caller ownership and shared-offset
requirements are the same as `ObserveSet`.

`OrderCompleteBlockSources(inventory, sources)` is a portable matcher for the
caller's already-observed generation list and already-open descriptor records.
It requires non-nil inputs, exact cardinality (bounded by `MaxSources`), valid
unique inventory generations and exactly one non-nil `*os.File` object per
generation; it rejects subsets, extras, duplicate generations and a Go file
object reused for multiple generations. The returned records follow inventory
order. Explicitly empty non-nil inputs are accepted. This helper compares only
the supplied metadata: it cannot prove that kernel enumeration was complete,
that devices are eligible or unmounted, or that a file descriptor actually
refers to its claimed generation. Callers must establish those discovery
preconditions and then use `ObserveBlockSet` for the descriptor `fstat` and
`BLKGETDISKSEQ` checks. It is not itself discovery or mount authorization.

`MatchUUID` reports `not-observed`, `one-object` or `conflicting-objects` only
within that set. Regular-image hard links share an object key (device/inode);
block-node aliases share a key (rdev). Different objects with the same UUID
are conflicts. Inconsistent results for one object invalidate the snapshot.
Names, bays and enumeration order are not treated as persistent identities.
Returned source indices refer to this call only, not approved mount sources.
Results are copied; all retained descriptors close before the snapshot returns.
Even `one-object` cannot prove global uniqueness, health or WD compatibility.
Physical media replacement, device-number reuse and multipath topology need
additional broker qualification; these keys are not durable disk identities.

Host tests exercise successful descriptor handoff and caller ownership,
environment/argument isolation, malformed/missing/unknown fields, output
overflow, nonzero/stderr failures, source-kind mismatch, descriptor refusal,
concurrent file modification, interruptible-process cancellation and the
single-slot rule. A fixed-count fuzz target checks the response decoder.
Set tests add alias/clone grouping, missing UUIDs, whole-set refusals and a
competing write to an earlier image during a later probe.
The complete Linux/amd64 package suite has run successfully, including
generation-set validation and regular-file refusal. This does not exercise a
successful disk-sequence ioctl against a block device.
The QEMU unmounted-disk fixture calls this implementation, not a separate
copy of the process/JSON code, including clone/alias distinction before
mounting. Its generation-bound path also checks a deliberately stale expected
sequence is rejected without a partial snapshot; this is a fixture assertion,
not yet evidence that the updated guest smoke has run.
It also verifies a generated ext2/XFS collision through the real ARMv5 helper:
individual signature controls succeed, the combined image returns `ErrProbe`
without identity, and a set containing that image returns no partial results.
Generated-image hashes stay unchanged. Block I/O failure and device replacement
remain separate unqualified cases.

The future trusted broker still must establish eligible devices, discovery
completeness, unmounted state, exclusive access and identity stability before
and after this primitive. It must reconcile duplicate UUIDs and qualify WD
layouts before any mounting or SMB/NFS lifecycle action. No such activation
path is implemented. See the [native helper](../../phantowd-volume-probe/README.md)
and [mounted identity guard](../mountguard/README.md).
