# Administrator credential transactions

This package is the Linux persistence prerequisite for panel password changes.
It is **not yet the running API's account backend**: the existing setup/login
flow still uses its setup-only version-1 writer. Do not open both writers on
the same directory. No password-change endpoint, reset, recovery UI, default
password, Unix/Samba account operation or hardware mutation is added here.

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

## Controller integration still required

The store accepts an already-derived verifier, not authorization. The future
adapter must verify the current password against a particular loaded revision,
enforce bounded KDF work, commit that revision, and coordinate session revocation
with login issuance. An uncertain commit must deny authentication/authorization,
not use an old in-memory account. Existing sessions must not bypass that state.
Lost responses need explicit reconciliation, not a blind retry with a newer
revision. Recovery, product state provisioning and downgrade rules remain open;
the old version-1 reader deliberately rejects version 2.

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
