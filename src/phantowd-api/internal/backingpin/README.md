# Existing file metadata pins

Linux-only internal prerequisite for M9.1b, not a writable LUN capability.
`Open` borrows a caller-owned qualified `mountguard.Root` and retains its own
parent/leaf `O_PATH` references to one existing, regular, single-link file of
an exact 512-byte-aligned expected size. No fallback to weaker syscalls exists.

Resolution denies symlinks/magic links, traversal and nested mounts (including
same-filesystem binds). Verification independently resolves the named parent
and file and compares them with the retained identities, bracketed by Root
checks. Mount identity/type/flags, inode, size, mode, UID/GID and link count
participate; timestamps and allocation counters do not. Filesystem read-only
state and allocated sectors are observations, not permissions, extent coverage,
reserved space, filesystem integrity or capacity admission.

Any observed drift or uncertainty permanently marks the pin `review`; restoring
the pathname never revives it. Retained references stay owned until explicit
serialized `Close`. Close uncertainty remains explicit on subsequent calls;
there is no automatic reopen/retry. The borrowed Root is not closed by the pin.
The Root's lifecycle owner must coordinate concurrent revocation and consumers.

## Retained mounted-roster constructor

`OpenFromMountedLease` accepts an existing complete `mountowner` roster lease,
not a desired policy or raw Root. It holds a private member-root pin until all
metadata references are closed; the group's direct `Close` returns busy while
that pin exists. The writable prototype therefore retains the mount lifetime
through confirmed consumer stop, and through uncertainty without a close bypass.

Root checks cover the entire original roster under canonical locks. Directory
references are independently caller-owned, not Owner-tracked handles that would
accumulate on repeated verification or be closed twice. Observed drift is sticky;
uncertain reference closure retains the root claim. Explicit root-pin release
does not release the group or unmount it. This is an internal ownership contract,
not enforcement against unrelated privileged processes or a product opener.

The disposable ARMv5 fixture checks actual mounted-owner composition, failed
file admission without a stranded lease, constant descriptor count across32
verifications, caller-close refusal, normal/replace/exit/uncertain consumer
lifetimes, and a separate actual same-filesystem overmount retaining its
independent root descriptor until release. The overmount test is metadata-only,
not proof of an actual writer stopping on mount loss or product recovery.

## Private writable-reference lifecycle prototype

`writable_linux.go` contains an unexported owner/constructor, used only by
package tests and the QEMU fixture. It accepts an already-open RW descriptor,
compares its real metadata/flags with the Pin before and after, and on success
exclusively claims Pin/file/backend ownership. Foreign descriptors, read-only,
append or missing close-on-exec flags refuse without taking ownership. It is
not a production opener or an access/allocation/global-use admission token.

The fixed backend is retained at construction, never supplied per operation.
Start checks before and after readiness; caller-driven observation checks file
identity and consumer state. Drift/exit/uncertainty quarantines and makes one
stop attempt. Confirmed stop precedes RW descriptor and metadata release;
uncertain stop retains both references, denies Pin close and cannot be retried
or bypassed through owner close. Active owner close is busy, not implicit stop.
There is no restart, background monitor or product recovery implementation.

Native state-machine tests use a private checker seam, explicitly not real
descriptor admission. The QEMU fixture additionally uses the actual Root and
real RW descriptors, with a fixed UID/GID1000 static Go child writing via an
inherited descriptor, without a shell or second exec. Thirty-two credential
observations after the write guard against readiness/exec races. It verifies
write/readback, stop/reap-before-release,
replacement preservation, unexpected exit, concurrent stop and retention on
uncertainty. Independent test-only teardown reaps the synthetic child after
assertions; it does not revive the reviewed owner or implement product recovery.
This fixture is not a LIO backend or qualified process-isolation profile.

No descriptor/path/raw identity is exposed. Handles/observations reject JSON.
The public metadata pin performs no data read/write/create/truncate. Neither
it nor the private lifecycle prototype supplies product writable authority,
mount qualification, global-use/session fence, credential access, configfs, listener, HTTP or
product startup. Verification is point-in-time, not proof of change history or
unchanged file contents. Metadata syscalls can still perform/block on metadata
I/O; this is not a universal execution deadline.

Native tests explicitly skip actual positive lifecycle cases when the host
kernel lacks `STATX_MNT_ID_UNIQUE`; synthetic metadata/mask/input checks still
run. The QEMU-only fixture uses the real Root on known disposable ext storage,
not an untrusted path-derived UUID. It tests metadata-only descriptors, missing
and unsafe objects, replacement/unlink/size/mode/UID/GID/link/parent changes, restoration
quarantine, concurrent verify/close and uncertain close. Its caller additionally
tests nested/leaf bind mounts, private read-only transitions and Root loss.
Mandatory smoke assertions require these tests; no physical disk is involved.

Remaining M9.1b work: qualified production lifecycle and coherent policy binding,
controlled writable descriptor acquisition/handoff and retained lifetime,
permissions/allocation admission, whole-protocol backing-use/session ownership,
protected credentials, backend observation and verified teardown. Do not use
this metadata-only pin as a substitute for those capabilities.
