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

Close waits for the active operation, closes all stores and the bound Samba
executor/config descriptor exactly once, then releases the lease.
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
