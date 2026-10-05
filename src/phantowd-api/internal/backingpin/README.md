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
independent root descriptor until release. Additional actual same-filesystem
overmount cases retain a live UID/GID1000 inherited-RW consumer: observation
quarantines and confirms stop/reap before reference release, or retains the
live child/RW/metadata/mount claims when stop is deliberately uncertain.
Restoring the exact original bind cannot revive the consumer, retry stop or
issue a fresh lease. Independent confirmed fixture teardown releases references
before the reviewed mount is removed. The child writes once and holds its FD;
this is mount-identity loss, not physical I/O failure during a transfer, a LIO
target/session test, autonomous supervision or product recovery.

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
There is no restart, detached background monitor or product recovery implementation.

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
mount qualification, global-use/session fence, production credential authority, configfs, listener, HTTP or
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

## Private coherent-policy lifetime composition

An unexported constructor acquires its own `naspolicystore` revision claim and
matches the selected BackingID against the retained mounted VolumeID, relative
file name and exact size before using the existing RW descriptor admission.
Failed construction releases its provisional claim without consuming the
caller's Pin, file or backend. This is reference matching, not target enable,
registry/media qualification, access, allocation or credential authority.

Start and observation bracket kernel/readiness checks with policy verification.
Confirmed consumer stop/reap and successful RW/metadata/mount-root reference
closure precede private policy release. Uncertain stop or reference closure
retains the claim and its Commit/Close fences; restoring policy cannot revive
the consumer or retry teardown. Policy checks do not hold policy locks while
acquiring Pin/mount locks. Supervision is an explicit blocking operation below,
not a detached monitor or product startup hook.

Tagged native tests exercise claim fencing, before/after-start drift, failed
admission and actual file-close failures; their lifecycle checker seam is not
qualified descriptor admission. Actual disposable ARMv5 cases compose the
mounted owner and inherited-RW UID/GID1000 child with normal shutdown, restored
policy mutation and uncertain stop. The existing two actual same-source
overmount/loss cases now retain a private policy claim too. Independent fixture
cleanup confirms child teardown before releasing references; it is not product
recovery. The desired target remains disabled: this independently authorized
static test child is not LIO or product activation.

## Explicit private supervision

`supervise(ctx)` accepts only an already-active consumer and exclusively owns
its lifecycle until return. Concurrent start/observe/stop/close/supervise calls
refuse busy. One complete scan runs immediately; subsequent scans start after
a fixed one-second idle interval, not a ticker/catch-up queue. No scan overlaps,
and supervision never starts or restarts a consumer.

Accepted cancellation requests stop using a fresh five-second operation context;
confirmed stop/reap and successful reference closure precede policy release.
Drift, exit, timeout or stop/close uncertainty retains terminal review without
retry. An already-canceled, unaccepted request has no effect. The trusted backend
must honor its context; metadata I/O may block and the timeout is not a universal
wall-clock guarantee. No production polling/resource budget is qualified yet.

Native race tests cover exclusion, accepted/unaccepted cancellation, cancellation
during a scan, private policy fencing, source/exit/observation faults and uncertain
closure. Actual disposable ARMv5 tests supervise cancellation, restored policy
mutation, uncertain stop and a real unexpected child exit. Both actual mounted-
loss cases now run under supervision, not manual observation. Old cases remain
mandatory. The explicit test goroutine must be joined before independent disposal;
live supervision blocks that cleanup. This adds no boot/profile, HTTP surface,
product startup, LIO backend or permission to open data.

Windows preflight/cross-compilation, pinned Linux tagged vet/race, focused race
count3, shell/storage contracts, actual ARMv5 standard smoke and the complete
two-boot fixture pass locally. These are cache-reusing userspace-overlay tests,
not clean-build, physical-storage or EX4 qualification.

## Private credential-bound lifetime composition

An additional unexported constructor acquires its own coherent policy claim,
checks target-to-backing membership and obtains a private claim from the
[root-only CHAP reader](../iscsicredentials/README.md). The same fixed backend
receives credentials and owns execution. Preparation is inside the started
lifecycle: even a partial/uncertain prepare requires verified backend teardown
before release. Fresh credential checks bracket policy/kernel observations.

Credentials remain retained through uncertain stop or reference closure. No
per-operation backend injection, automatic rotation/restart or product writer
is added. Owned handles deny JSON and redact `fmt`, including copied values.
Root-only synthetic native tests cover preparation/drift/close uncertainty;
three added disposable mounted QEMU cases check normal stop, exact restored
secret mutation and uncertain stop with the actual UID/GID1000 child. The secret
sink stays in the root fixture; no secret enters child arguments/environment
or logs. Those single-backing cases do not prove LIO authentication or
target-wide/multi-LUN admission; the complete resource prototype below adds
the latter lifetime boundary, not product activation authority.

## Private complete-target resource lifetime

The unexported target constructor reuses the same lifecycle and supervisor,
not a second state machine. It privately retains one coherent policy claim,
one credential bundle and the complete selected target's existing Pin/RW file
roster. Missing, extra, foreign or duplicated members refuse. Explicit LUN
numbers determine ordering; input positions do not. Distinct handles or bind
mount IDs cannot disguise the same observed inode/device. This metadata alias
check does not establish physical allocation or global backing-use authority.

Every member must independently match the retained policy and pass real
descriptor/root checks. Provisional claims use one Pin lock at a time; failed
admission returns caller references without closing them or preparing a backend.
Already observed review remains sticky. The fixed backend receives a defensive
roster copy and borrows every data handle. Its successful stop must join **all**
processes, sessions and kernel credential users. Complete scans observe every
member; drift in a later LUN cannot be hidden by a healthy first LUN.

Confirmed whole-backend teardown precedes every data close. All data closes
must succeed before any metadata Pin is released; successful Pin/mount-root
closure then precedes policy/credential release and owned-buffer wiping. Stop
uncertainty retains all sources. Close uncertainty retains the remaining
references and global claims in review; already closed files stay closed and
teardown is never retried. This is not durable product recovery.

Native tagged race tests cover complete planning, aliases, second-member drift,
partial start/close faults, cancellation and credential retention, with the
explicit lifecycle seam. Actual ARMv5 QEMU additionally tests real mounted
two-file admission, failed second-descriptor rollback, explicit LUN0/LUN7 order,
512/4096-byte metadata, second-file replacement and uncertain stop around a
UID/GID1000 child inheriting both files. The fixed child validates both files
before writing public markers; credentials remain in the root fixture's sink.
Standard smoke and the existing complete two-boot lane pass without another
kernel build or boot profile. This is descriptor/resource lifetime proof, not
LIO installation, protocol authentication or qualified access enforcement.

No product opener, allocation, registry/global-use/session/network authority,
HTTP, listener, startup, physical disk or NAS operation is added. Desired target
enable/access remains metadata, not permission to run or expose a target.

## Private typed LIO credential sink prerequisite

The Linux-only sink is a fixed-consumer prerequisite, not a target backend.
It borrows backend-owned TPG/auth directory references, requires root-owned
writable configfs with unique mount/inode observations, and rechecks each named
ACL's confined `acls/<initiator>/auth` topology against its borrowed descriptor.
Same-filesystem or similarly named handles do not establish that relationship.
Only fixed credential/state leaves may be opened: no create/truncate, arbitrary
path, ACL/portal/LUN creation, target enable or credential release exists here.

The complete credential roster is matched before mutation. One installation
attempt writes opaque secrets directly through their trusted sink interface;
fixed-size transient readback compares exact bytes plus the pinned kernel's
single show newline, then wipes its scratch. No secret string/digest, diagnostics
or independently retained secret byte copy is returned. CHAP explicitly unsets
stale outbound fields; this is logical unsetting, not guaranteed kernel memory
erasure. Reciprocal configuration is not required-mutual enforcement.

Installation and private verification bracket all field operations with disabled
TPG/root/topology checks. Partial write/read/close, observed drift or uncertainty
permanently enters review; no reinstall, clear, rotation, restart or recovery
method exists. The containing backend must own exclusive configuration access
and retain claims until all kernel borrowers and configfs objects are verifiably
torn down. Disabled-state snapshots alone are not session/global-use authority,
continuous change-history proof or an atomic transaction. Metadata I/O can block;
context cancellation is not universal syscall interruption.

The separate tagged fixture provisions a public synthetic root-only vault and
two successive fixed loopback targets with **zero data LUNs**. It exercises
the actual configfs sink, CHAP/reciprocal login through pinned libiscsi, wrong/
missing credential refusal, stale outbound removal, observed/restored drift
quarantine, claim retention and object teardown before release. It adds no data
disk or product activation. Native readback tests explicitly use regular-file
I/O seams, not positive configfs qualification. The dedicated guest fixture is
not installed in the standard overlay or shipped as a product service.

Remaining M9.1b work: qualified production lifecycle and full coherent policy admission,
controlled writable descriptor acquisition/handoff and retained lifetime,
permissions/allocation admission, whole-protocol backing-use/session ownership,
product credential generation/install/rotation, backend observation and verified teardown. Do not use
this metadata-only pin as a substitute for those capabilities.
