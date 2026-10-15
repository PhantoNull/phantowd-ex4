# Private SMART descriptor-generation witness

Linux-only M8.5b prerequisite, not a command/device provider. `Retain` borrows
an already opened `O_RDONLY` block descriptor, creates its own CLOEXEC duplicate
under `SyscallConn.Control` and checks device type, access flags, major/minor and
`BLKGETDISKSEQ`. Closing the caller's descriptor does not close that duplicate.
It accepts no path, reads no content, sends no transport command and changes no
capability. There is no HTTP/RPC, broker integration or normal startup call.

`Check` revalidates that same retained descriptor. A failed observation keeps
the duplicate in permanent review; restoration cannot resume the handle.
Operations refuse concurrent use and value copies. `Close` explicitly releases
only this duplicate; no child/command uses it and this is not a capture Owner.
The witness exposes neither a descriptor nor serialized identity evidence.

Matching generation is transient evidence, not stable media identity, topology,
whole-disk status, current pathname identity or command authorization. The
trusted caller must independently qualify complete leaf discovery and reconcile
the entire census. BLKGETDISKSEQ may also succeed on a partition: only the
validated whole-leaf census can establish that prerequisite. A shared file
description can change status flags; each Check revalidates access/O_PATH.
Context checkpoints do not interrupt an uninterruptible kernel ioctl. No
physical standby, transport support or hot-unplug behavior is established.

Native tests cover observation predicates, real non-block refusal, caller
ownership, copies/busy/cancellation, review and explicit release. The opt-in
QEMU MD fixture checks actual generation ioctls against its already-active
temporary members, wrong expected sequence, caller close and sticky review.
Review drift is an intentionally modified expected tuple, not physical hotplug.
Its root fixture does not qualify least-privilege product deployment.

## Complete-census fixed opening (private Linux composition)

The API package's private
[`openSMARTCensusWitnessSet`](../../smart_census_open_linux.go) derives every
name/generation from one complete, bounded sysfs census and uses the existing
fixed `/dev` read-only/no-symlink opener. It keeps the original pre-open census,
not a freshly adopted replacement, across generation checks. In-use leaves and
ambiguous/missing VPD stay visible; none becomes stable identity or eligibility
for SMART commands. There is no public selected-disk/path/argv input.

Constructor-opened descriptors transfer to the constructor. It retains its own
independent witnesses and closes those originals before successful publication;
the existing borrowed-source constructor never closes caller-owned originals.
At most 32 witnesses remain, one per whole leaf, with at most twice that many
descriptors during construction. Any uncertain close retains a non-usable owner
AND error in sticky review; the caller must keep that handle and never infer
admission from non-nil alone. No failed close is retried. Underlying fixed-opener
rollback retains its existing contract, not a newly proven kernel-close-fault
guarantee.

Linux unit/race tests cover invalid/canceled/incomplete inventories, exact
names/generations, missing/duplicate/non-block results, partial-opener-error
cleanup, pre-open baseline preservation and synthetic uncertain-close retention.
The existing ARMv5 MD fixture additionally opens all seven real virtual leaves,
checks only generation metadata, verifies no extra original FDs remain, and
refuses failed post-open census with no leaked source/witness descriptors.
These are root disposable-QEMU proofs, not non-root, hotplug, power-state or
physical transport qualification. No SMART report or command is admitted.

From the repository root, `support/test-api-overlay.ps1 -ReuseBaseVolumeProbe`
rebuilds the API and runs the standard smoke using trusted unchanged base kernel,
packages and C helper. The smoke-only lane skips the separate two-boot test and
does not regenerate the whole firmware image, package metadata or SBOM. The new
exact receipt is mandatory; missing/duplicate/suffixed records fail. No new
image/volume is required, no product startup or broker operation invokes this
constructor, and opening a device does not establish no-wake behavior.
