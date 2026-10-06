# Administrator credential transactions

This package is the running Linux API's administrator persistence backend and
the persistence layer for authenticated panel password changes. The former setup-only file writer
has been removed. Do not run older API binaries alongside this backend on the
same directory: they do not honor its lifetime lock. The API now provides a
current-password-verified change endpoint and form. No reset, recovery UI,
default password, Unix/Samba account operation or hardware mutation is added.

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

The store accepts an already-derived verifier, not authorization. The API's
password-change transaction verifies the current password against one snapshot,
derives a new verifier with the process-wide KDF bound, then locks and rechecks
that exact snapshot and request cancellation. Under the account lock it rechecks
the invoking session/CSRF and revokes all sessions/issuance epochs before the
revision-checked commit. Issuance uses the same account-to-session lock order.
New logins crossing the commit cannot use an obsolete verifier/issuance epoch.
Failure after revocation leaves sessions revoked and the account process
quarantined; it does not restore old sessions or automatically retry a write.
Previously authorized jobs/requests and SMB/NFS sessions are outside this scope.
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
reset attempts fail. Both fixture accounts now change through the authenticated
HTTP handler on boot one and enter the real login/session handlers on boot two.
The standard QEMU smoke additionally changes a password over real loopback TLS
and verifies old-login denial/new-login success. These are software tests, not
power-loss testing, EX4 state-volume qualification or a flashable image.
