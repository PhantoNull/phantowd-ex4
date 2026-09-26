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
The QEMU unmounted-disk fixture calls this implementation, not a separate
copy of the process/JSON code, including clone/alias distinction before mounting.

The future trusted broker still must establish eligible devices, discovery
completeness, unmounted state, exclusive access and identity stability before
and after this primitive. It must reconcile duplicate UUIDs and qualify WD
layouts before any mounting or SMB/NFS lifecycle action. No such activation
path is implemented. See the [native helper](../../phantowd-volume-probe/README.md)
and [mounted identity guard](../mountguard/README.md).
