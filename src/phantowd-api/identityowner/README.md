# Native identity authority owner (Linux)

This is the cooperative owner of one configured native-account reservation
ledger and its creation journals. It coordinates allocation, durable creation
intent and typed Unix execution under one lifetime root-directory lease and
one non-queuing operation mutex. It is a library, not an installed daemon or a
complete user/credential manager. The production HTTP service never opens it.

## Storage and ownership

`Open(directory, inventory)` requires already-root code, a clean absolute
path without symlinks/magic links, trusted parents, and these pre-provisioned
root-owned 0700 directories on one qualified local filesystem:

```text
authority/
  registry/       # explicitly initialized serviceaccountstore ledger
  operations/     # initially empty; one private journal directory per account
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
directories, account mismatches or inconsistent revision histories. This initial
owner supports only disabled native reservations created through its own flow;
legacy/foreign ledgers and later enable/retire histories are not imported.
One incomplete or review-required operation freezes further allocations.
Ordinary reserved/group-confirmed work reports ErrPending; interrupted intent
or review-required work reports ErrReview. Pending does not imply corruption.

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

Close waits for the active operation, closes all stores and releases the lease.
Context cancellation is cooperative and does not undo committed mutations or
bound uninterruptible filesystem I/O. Do not copy an Owner. Return values and
snapshots do not grant lasting Unix/Samba authorization.

## Remaining product work

Protected listener/service provisioning, complete inventory and supported legacy
import, durable EX4 state placement, explicit orphan/review recovery, credential-
aware enable/disable/retire transitions, Samba passdb coordination, HTTP/user
authorization and panel account management remain necessary. No firmware or
production storage deployment is authorized by this library.

Tests use generated temporary metadata and modeled Unix identities, including
real process exit between journal and ledger publication, competing owners and
store writers, stale revisions, pending-operation allocation refusal, quarantine
and concurrent requests. The guarded ARMv5 scenario uses the actual owner,
typed BusyBox executor and unprivileged socket client, closes/reopens the owner
between group and user creation, and verifies the no-login identity and cleanup.
