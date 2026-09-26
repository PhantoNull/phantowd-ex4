# Administrator credential transactions

This package is the running Linux API's administrator persistence backend and
the prerequisite for panel password changes. The former setup-only file writer
has been removed. Do not run older API binaries alongside this backend on the
same directory: they do not honor its lifetime lock. No password-change endpoint,
reset, recovery UI, default password, Unix/Samba account operation or hardware
mutation is added here.

## Contract

- `Open` requires a dedicated existing 0700 directory owned by the effective
  UID, under trusted parents, on a local filesystem supporting flock, rename
  and fsync. A retained descriptor and exclusive advisory lifetime lock scope
  fixed-name access. All writers must cooperate; this is not protection from
  malicious root, directory replacement by another authority or disk rollback.
- `accounts.json` must be an owned regular 0600 single-link file, at most 4096
  bytes. Its version-2 document contains a nonzero uint64 revision and one
  administrator name/Argon2id verifier. There is no plaintext password, session
  or file-service identity in this file. Snapshots must not enter HTTP/logs.
- The exact compact legacy version-1 encoding remains readable as logical
  revision 1 with the same identity/verifier. Reading does not rewrite its
  contents. Explicit successful replacement publishes version 2, revision 2.
  Unknown, missing, duplicate, null, noncanonical or corrupt fields fail closed.
  This is compatibility with the project's prototype, **not WD credential import**.
- `Initialize` only commits revision 1 to absent state. `Replace(expected,
  verifier)` preserves the name, requires the current revision, validates a
  different bounded verifier and increments once without wraparound. There is
  no arbitrary-document commit, delete/reset, name change or revision bypass.
- The shared transaction engine syncs the staged file, renames it, then syncs
  the directory. A rename/directory-sync error returns `ErrUncertain` and blocks
  reads and writes until close/reopen/reconciliation. No cached verifier is
  served. Other store errors retain the internal revision-store sentinels.
  A successful reopen validates/syncs the current file; it never promotes a
  pending file or repairs corrupt evidence automatically.

## Controller integration and remaining lifecycle

The adapter owns the store until shutdown. Initialization writes v2; existing
v1 accounts remain readable without content rewrites. Each account check loads
validated state, with no verifier cache. Login rechecks its complete snapshot
after bounded KDF work and session issuance makes a final account check under
the adapter lock. Existing sessions do not bypass unavailable credential state.
An observed storage error, uncertain initialization, invalid document or loss of
previously configured state latches unavailability for the process lifetime.
Putting a file back cannot revive its sessions or enable enrollment. Explicit
process restart reopens/reconciles storage and starts with an empty session map.
This is refusal behavior, not an automated recovery procedure.
The latch is process-local: after a restart an absent file in an otherwise
valid empty directory is still indistinguishable from first enrollment. A
durable product ownership/bootstrap authority is required before deployment;
this prototype must not claim to prevent re-enrollment after total state loss.

The store accepts an already-derived verifier, not authorization. A future
password-change endpoint must verify the current password against a particular
revision, commit that revision, and atomically coordinate session revocation
with login issuance. The adapter currently exposes initialization/read only;
the store's replacement method is exercised by isolated fixtures, not HTTP.
Lost responses need explicit reconciliation, not a blind retry with a newer
revision. Recovery, product state provisioning and downgrade rules remain open;
the old version-1 reader deliberately rejects version 2.

Non-Linux binaries refuse persistent administrator state. Host HTTP/TLS tests
on those platforms explicitly inject a test-only memory backend; they do not
prove filesystem durability. Actual Linux/ARMv5 runs use this store, without a
memory fallback. The normal QEMU profile still chooses volatile `/run` state.

Do not conflate atomic publication with blackout qualification. Store errors
do not guarantee that a write did not happen. An explicit close/reopen can
re-establish a filesystem sync boundary but cannot recover inaccessible media
or make an unknown device layout safe.

## Validation

Host tests cover canonical legacy preservation, initialization/reset refusal,
concurrent and stale replacements, revision exhaustion, malformed/unsafe state,
staging obstruction, no cached credentials after corruption, reopen and a real
child-process exit after commit but before acknowledgement. The shared engine
has separate write/sync/rename fault-injection and process-exit boundary tests.
A bounded decoder fuzz lane is included in the pinned Linux suite.

The isolated two-boot ARMv5 fixture tests both native initialization and legacy
conversion on a generated disk. It retains a newer uncommitted pending file
containing the obsolete verifier, then requires the committed replacement to
survive reboot: the old password fails, the new one succeeds, stale writes and
reset attempts fail. This is store/KDF evidence, not an HTTP password-change
flow, power-loss testing, EX4 state-volume qualification or a flashable image.
Its second boot now additionally enters the real API account adapter and login/
session handlers: obsolete-password login fails and the retained replacement
issues a usable panel session. These are handler-dispatch tests; the separate
standard QEMU smoke covers real HTTP/TLS and API-process restart.
