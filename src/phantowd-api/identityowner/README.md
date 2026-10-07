# Native identity authority owner (Linux)

This is the cooperative owner of one configured native-account reservation
ledger, native creation journals and optional Samba-enrollment journals. It
coordinates allocation and typed Unix/Samba operations under one lifetime
root-directory lease and one non-queuing operation mutex. It is a library, not
an installed daemon or a complete user/credential manager. The production HTTP
service never opens it.

## Storage and ownership

`Open(directory, inventory)` requires already-root code, a clean absolute
path without symlinks/magic links, trusted parents, and these pre-provisioned
root-owned 0700 directories on one qualified local filesystem:

```text
authority/
  registry/       # explicitly initialized serviceaccountstore ledger
  operations/     # one private journal directory per account
    <account-id>/
      smb/        # created only for an attempted Samba enrollment
```

Open neither creates those directories nor initializes/imports/resets a ledger.
It retains an exclusive advisory lease on the authority root, the ledger store
and every known operation store until Close. The retained operation stores avoid
reopening/fsyncing every journal for every status read. All processes managing
this authority must use this same configured root and honor its ownership;
other root tools or instances pointed at different roots are **not** excluded
from changing `/etc`. The product must enforce a single writer deployment.
No directory may be independently moved, replaced or modified during ownership.

`Close` drains active work and refuses retained file-service consumers. It
closes the startup-bound backend **before** releasing any journal or ledger.
Any backend close error retains all these authority leases and the backend,
returns redacted `ErrUnavailable` and `ErrReview`, and rejects further work.
Repeated `Close` returns the same classification without replaying teardown,
even if the backend could now succeed. After verified backend closure, an inner
store/operations close error retains the outer root fence; some inner stores
may already be closed. Final root-descriptor close failure is sticky too, but
cannot prove that a failed system call retained that descriptor. No descriptor
number is retried and no qualified recovery is provided by this library.

Root-isolated regression tests use real stores and filesystem locks, with only
the external backend's uncertain teardown modeled. They prove competing Owner,
registry and native/Samba journal refusal after the backend error, fail-closed
observations and no automatic retry. A separate positive test verifies journal
authority during backend teardown and normal idempotent closure. The fault test
runs in a disposable subprocess to contain deliberately retained descriptors;
its process-exit cleanup is not a product recovery qualification. Failed-Open
cleanup, low-level close faults and complete runtime/product recovery still
require separate lifecycle qualification.

Snapshots freshly decode the ledger/journals and refuse missing/orphan entries,
wrong ownership/modes, symlinks, device changes, replaced known operation
directories, account mismatches or inconsistent revision histories. Registry
desired state may be `disabled` or `enabled`, while the immutable native journal
continues to describe the disabled identity originally reserved and created. On
reopen, an interrupted Samba command intent is durably converted to
`review-required` without observing Samba or replaying a command. Legacy/foreign
ledgers, retired accounts and unsupported native-identity histories are not
imported. One incomplete or review-required native creation freezes further
allocations. Ordinary reserved/group-confirmed native work reports ErrPending;
interrupted native intent or review-required native work reports ErrReview.
Pending does not imply corruption.

`FileServiceSnapshot(ctx)` is a separate in-process, all-or-error evidence
reader for a future file-service planner. Under the same Owner lock, it checks
the complete registry and known journals, re-observes every managed Unix
identity, takes one batched redacted passdb observation for every managed
account name, and correlates each result with its Samba journal. This is not a
global inventory of unrelated Samba accounts or external identity providers.
A pre-existing passdb entry without an Owner journal, a mismatch, an
interrupted command intent, or any review-required Samba journal refuses the
whole snapshot before passdb observation; uncertain intents are not recovered
or rewritten. It returns sorted local UID/GID/name reservations
plus a SHA-256 evidence fingerprint. The snapshot blocks JSON marshal/unmarshal
because the evidence is host-private. The
Linux-only `fileserviceplan.IdentityFromOwner` adapter now maps this evidence
into a non-serializable planner snapshot; a disposable ARMv5 QEMU Owner fixture
checks the adapter and verifies identity changes invalidate old plans. The
fixture uses an empty policy and synthetic empty storage. This is not product
startup, RPC/HTTP wiring, activation or a fence against unrelated root writers.
A current-source ARMv5 QEMU smoke also exercises `FileServiceSnapshot` itself
after the existing disposable SMB fixture has explicitly enabled one of its
two Owner-ledger accounts: the snapshot correlates the redacted passdb row,
confirms the second account has no adopted passdb entry, checks local UID/GID
reservations, and proves both native and Samba journals are unchanged across
observation. The snapshot call adds no authentication transition; the
surrounding fixture's SMB lifecycle remains disposable test state only.
A separate ARMv5 fixture composes the same Owner identity/local UID/GID
evidence with the mount-owner-observed tuple of a disposable ext2 volume in an
NFS-only read-only candidate. It rejects stale identity or storage fingerprints
and performs no Samba enrollment or export activation; inputs remain test
fixtures, not production storage qualification.

`WithFileServiceSnapshot(ctx, inspect)` keeps the same lock through a bounded
trusted in-process inspection callback, for example when a future planner must
compose identity evidence with independently locked storage evidence. Callbacks
must not re-enter this Owner or perform process, filesystem, network, or
activation I/O. The snapshot itself uses the non-recovering scan path; ordinary
`Owner.Open` startup recovery remains unchanged. Interrupted or review-required
intent makes the complete observation fail closed without passdb reads, replay,
or journal rewrites.

## Native enrollment lookup

`NativeLookupSnapshot(ctx)` and `WithNativeLookupSnapshot(ctx, inspect)` are
trusted in-process read-only operations, not socket/HTTP methods. They collect
the validated registry, confirmed native journals, existing stable Samba
journals and fresh complete local Unix reservations under the same mutation
lock. Desired-disabled native accounts are included even before Samba
enrollment; no Samba backend is required or queried. An empty ledger still
requires an explicit complete Unix observation.

Incomplete or mismatched native identities, interrupted/review Samba journals,
unknown/replaced stores and incomplete Unix observations refuse the whole
result. No intent is recovered, journal rewritten, credential observed or
command dispatched. The native checks are shared with `FileServiceSnapshot`;
that stronger reader retains its existing batched passdb requirement and
fingerprint format. Both convenience readers return zero evidence on error.

Lookup fingerprints use a separate domain and cover registry, native/stable
Samba journals and the complete local UID/GID/name census. They detect even
desired-state or foreign-census changes, but do not retain authority or freeze
files. Returned collections are independent of the Owner stores and JSON
marshal/unmarshal is refused. Callbacks permit only bounded in-process
derivation: no reentry, staging I/O, subprocesses or service lifetime.

This evidence cannot establish passdb absence, enabled credentials, SID
freshness, share grants or mount/service readiness. The separate internal
`fileserviceplan.SambaEnrollmentLookupFromOwner` renders lookup-only documents;
the enabled-service planner remains unchanged. Staging, actual libc lookup,
same-state credential backend construction and product startup remain open.

## File-service consumer retention

`RetainSMBFileServiceSnapshot(ctx, expectedFingerprint, expectedBackend)` adds
an exact startup-backend identity requirement. The candidate must be the same
non-nil pointer object already fixed in `OpenWithSMBBackend`; equal snapshots
from another Owner/backend are insufficient. Value adapters, typed nils and
zero-sized pointees are refused. The argument only asserts identity: it is
never substituted or dispatched, and foreign binding fails before observation.
Its opaque lease shares the existing 16-consumer bound, close fence, sticky
review, copy semantics and serialization refusal. Verification checks that the
original backend remains bound, then collects the ordinary complete evidence.
The generic retention method below is unchanged and makes no SMB binding claim.

Root-run Linux/race tests verify equal-evidence foreign refusal, invalid object
identities, revocation/stale evidence, serialization, mixed consumer capacity
and exact backend lifetime. A separate actual ARMv5 native-backend read-only
probe verifies retention/close refusal and unchanged release **before** daemon
startup. It does not retain or supervise the live service. Consumers must still
construct against their own fixed runtime/backend, verify outside Owner/runtime
gates and obtain an explicit successor contract for confirmed account changes;
retention alone provides no atomic handoff, refresh, process authority or recovery.

`SMB(id).DisableForFileService(ctx, expectedRevision, currentLease)` is a
separate internal, explicit transition for a backend-bound consumer. Under the
same Owner lock it checks complete non-recovering evidence, the exact target
revision and Unix identity, then invokes the existing journaled `Disable` on
the startup-bound backend. A complete post-observation must differ only in the
target's enabled-to-disabled journal (revision +2) and its disabled passdb flag.
Registry, native journals, Unix census, SID/UID/GID and every other account must
remain unchanged. Only then is the retained slot transferred to a NEW opaque
token without a zero-consumer interval, including at capacity sixteen.

The old token is permanently invalid; its copies/releases cannot affect the
successor. Stale requests, foreign/unbound/released tokens or incomplete evidence
return no successor. Mutation/observation uncertainty retains the old reference
in sticky review, without retry, rollback or arbitrary fingerprint refresh.
A completed journal is not rewritten merely because later census drift denies
the service handoff. Enable/password rotation have no successor path here.

Root/race tests cover transfer, all pre-admission refusals, unrelated census
drift, revocation error/cancellation, capacity and concurrent Close. The actual
ARMv5 native fixture acquires a consumer before held clients, revokes the target,
verifies the old/new tokens and SAME peer session, and keeps the successor until
verified daemon/client stop. Preparation has a separate bounded 20-second phase;
live pair/revocation/login checks remain 45 seconds and the outer guest 180.
This fixture acquires after daemon startup: it does not qualify startup binding,
continuous supervision, storage grants, product activation or recovery.

`RetainFileServiceSnapshot(ctx, expectedFingerprint)` is a trusted in-process
operation, not a request field or RPC/HTTP route. It freshly collects the same
complete, non-recovering evidence under the Owner lock and retains a consumer
only if it exactly matches the prior snapshot/planner fingerprint. Zero input,
incomplete/review evidence, stale fingerprints, cancellation and busy admission
return no token. At most 16 consumers are retained; a released slot is reusable.
Do not call it, `Verify`, or `Release` inside the pure snapshot callback.

The opaque `FileServiceLease` provides `Verify(ctx)` and `Release()`. The
original Owner remains the only authority: its `Close` waits for active work
then returns `ErrBusy`, releasing nothing, while any consumer remains. Token
copies share one private state; repeated or concurrent release cannot drop
another consumer. JSON serialization/deserialization is refused.

Verification re-observes complete evidence under the same mutation lock. Drift
or an uncertain admitted observation permanently marks that consumer review;
restoring identical evidence does not revive it. Busy or cancellation before
admission gives no positive verification and does not itself mark identity
drift. Cancellation during an admitted observation is uncertain and sticky.
Unrelated changes to the complete local Unix census also invalidate the
fingerprint conservatively; this is not a selective foreign-account lease.

Consumers do not hold the mutex between calls or freeze passdb bytes. Explicit
desired-state changes, credential operations and account/session revocation
remain possible; the old lease will refuse changed evidence. `Release` drops
only the cooperative reference, closes no store/process and does not clear
review or close the Owner. A trusted service coordinator must stop and verify
all descendants before releasing current service-owned tokens. The explicit
verified transition above transfers a slot instead of releasing the authority;
discarding its superseded token never discards the successor. A probe with no launched
descendants can release after its observation ends. Required verification that
cannot complete is not permission for a service to continue operating.

These tokens do not independently bind the daemon to the same passdb/NSS/state
objects, exclude unrelated root writers, supervise/stop a process, provide general account transactions,
or implement product startup/recovery. Mutable credential content is not part
of the redacted snapshot; supported Owner mutations are represented through
the journals/revisions. Same-object state and single-writer deployment still
need qualification. See the [remaining product work](#remaining-product-work).

Root-run Linux tests exercise lifetime/exclusivity, stale admission, capacity,
copy/concurrent release, uncertain observation/cancellation and restoration.
Explicit revocation and disabled credential rotation remain available. The
actual disposable ARMv5 enrollment fixture also retains this Owner across its
existing enable/disable/re-enable cycle, verifies real new-login denial and
sticky review, and checks that release leaves its fresh evidence unchanged.
This probe launches no descendant and is not the daemon's complete service
Owner; it does not claim retained NSS/passdb/storage composition or full live
session-revocation proof under this token.

## Creation and interruption

`Reserve(ctx, expectedRevision, id, name)` merges protected local Unix exclusions
with a **trusted complete external/offline/imported ownership inventory** supplied
by the caller on each allocation. No production inventory implementation exists
yet. Nil/incomplete inventory must fail; an explicitly empty inventory is only
valid when the caller can establish that scope, as in the disposable QEMU test.
Paths, UID/GID and shell/command details are not reservation parameters.

The new private operation directory and initial journal are made durable before
publishing the ledger reservation. No native command runs in Reserve. If the
process exits between the documents, reopening finds an orphan and refuses
service; it never reuses its UID, deletes the evidence, adopts it or silently
completes the transaction. An error after directory creation quarantines the
current owner. This is conservative reconciliation, **not** an atomic two-file
transaction or an implemented recovery workflow.

`Operation(id)` exposes only context-aware Load and revision-checked Step for
the [local channel](../identityrpc/README.md). The ID is resolved against the
validated ledger before any path use. Step owns the coordinator lock across
fresh state checks, journal intent, the [typed executor](../identityexec/README.md)
and confirmation. Other reservations cannot invalidate the registry revision
mid-command. Resumed intentions require review, never command replay. After a
later reservation advances the ledger, old completed journals remain readable
but their old Step context is refused. State corruption or uncertain storage
quarantines the owner; no automatic repair or deletion is provided.

`SetDesiredState(ctx, expectedRevision, id, state)` is an in-process, revisioned
transition for the registry's desired service-account state. It accepts only
`enabled` or `disabled`, runs under the same Owner lease, refuses while any
native creation is incomplete/review-required, and revalidates the exact Unix
identity before committing. The native journal remains an immutable record of
the original disabled identity. This method does **not** enable/disable Unix or
Samba authentication, change share grants, revoke sessions, write daemon config,
or activate any service; enabled desired state is not evidence that SMB is
usable. It is not exposed through the Owner socket, HTTP, or UI. Retirement and
legacy identity migration still require a later coordinator.

`OpenWithSMBBackend` binds and takes lifetime ownership of one trusted
in-process adapter. `Open` without that adapter keeps SMB mutations
unavailable.
`SMB(id)` exposes in-process `Begin`, `Load`, one-step disabled entry creation,
stdin-only `SetPasswordDisabled`, and separate revision-checked `Enable` and
`Disable` actions, plus a read-only `Review` observation gated to an existing
`review-required` Samba journal. `Review` revalidates the Unix identity under
the Owner lock and returns only validated redacted passdb metadata; it never
recovers or changes a journal, invokes a mutator, or clears quarantine. These
operation methods cannot accept or substitute a backend. `Disable` blocks new authentication, revokes only the account's
existing sessions and verifies their absence, or records review-required on
uncertainty without replay. It can interrupt active transfers. Each method
uses the same authority lock. Mutations revalidate the exact Unix identity
before dispatch, and every Samba journal is bound to the confirmed Unix
account/revision; `Review` independently verifies the current identity.
Existing passdb entries are never adopted.
Uncertain/interrupted Samba intents become review-required and are never
replayed. A fixed Linux Samba executor exists and the QEMU fixture exercises
that exact adapter with a private disposable config. It verifies valid
credentials fail before explicit enable and succeed only after the same SID is
observed enabled. The executor is not yet bound into product service startup.
The internal version-2 Unix channel can transport the typed enable/disable
actions in QEMU but adds no HTTP endpoint; production
listener/startup/authorization wiring remains absent. Open-handle and durable
reconnect semantics are unqualified. See the
[internal `smbprovision` contract](../internal/smbprovision/README.md) and
[channel boundary](../identityrpc/README.md).

The disposable ARMv5 QEMU profile now starts a root Owner service from its
`S49phantowd-identity-owner` init hook. It opens the fixture's trusted SMB
backend once with the Owner, creates only guest-local `/run` state, and exposes
the Owner resolver through the protected Unix listener; it does not install a
product daemon or HTTP route. The boot fixture checks exact socket ownership and
modes, rejects a different UID that can reach the socket by DAC, preserves the
operation journal across a service-process restart, and verifies listener drain
before Owner close. After listener drain, a separate root Owner round-trips the
registry desired state disabled→enabled→disabled (revisions 2→3→4), verifies the
native journal remains disabled/unchanged, and confirms no Samba child journal
was created. The test causes no authentication mutation or service activation.
The QEMU validator also accepts the deliberately tested
`group-confirmed`-then-restart phase while continuing to reject other
incomplete/review-required phases. This proves a QEMU startup/lifecycle slice,
not reboot durability or product state placement.

Close waits for the active operation and refuses busy while consumers remain.
After their explicit release, it closes all stores and the bound Samba
executor/config descriptor exactly once, then releases the authority lease.
Context cancellation is cooperative and does not undo committed mutations or
bound uninterruptible filesystem I/O. Do not copy an Owner. Return values and
snapshots do not grant lasting Unix/Samba authorization.

## Remaining product work

Production listener/service provisioning and startup, complete inventory and
supported legacy import, durable EX4 state placement, native orphan recovery,
binding/configuration for the Samba executor and credential channel, explicit
orphan/review workflows, production collection of trusted storage evidence and
its transactional planner/service integration, production integration of
credential replacement and disable/revocation,
retirement, HTTP/user authorization and panel account management remain
necessary. No firmware or production storage deployment is authorized by this
library.

Tests use generated temporary metadata and modeled Unix identities, including
real process exit between journal and ledger publication, competing owners and
store writers, stale revisions, pending-operation allocation refusal, quarantine
and concurrent requests. The file-service evidence tests verify batched
read-only observation, stable evidence fingerprints, copy isolation, refused
serialization, and that an interrupted SMB intent remains byte-for-byte
unchanged. The guarded ARMv5 scenario uses the actual owner,
typed BusyBox executor and unprivileged socket client, closes/reopens the owner
between group and user creation, and verifies the no-login identity and cleanup.
Its Samba-enrollment fixture uses the same owner lock/journal and fixed Linux
executor with a disposable loopback `smb.conf`; it does not qualify product
startup/configuration, persistent passdb placement, or EX4 behavior.
