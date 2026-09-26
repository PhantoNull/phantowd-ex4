# SMB credential lifecycle: integration gate

Status: **design with pinned-upstream characterization; no product credential
executor or panel account-password endpoint is enabled**. Dashboard administrator
credentials are a separate system and are not affected by this Samba behavior.

## Why the existing CLI sequence is insufficient

The configured Samba source is 4.22.11, archive SHA-256
`d569b298a81cc212a39e9d1813bc4ca5c71ac93c4ceb2eec03db178096958d00`, matching
Buildroot's package hash. The relevant paths are:

- `source3/utils/smbpasswd.c`: option `-d` clears `LOCAL_SET_PASSWORD`, so combining
  stdin password input with `-d` does not perform a password update.
- `source3/passdb/passdb.c:local_password_change`: setting a password can clear
  `ACB_DISABLED` when the stored LM hash is absent. The disable flag is processed
  afterward, before `pdb_update_sam_account`.
- `source3/passdb/pdb_interface.c:pdb_default_create_user`: a new account is
  initially marked disabled before the backend adds it.
- `source3/utils/pdbedit.c:new_user`: account creation delegates to the same
  local password-change function. Switching tool names is not an atomicity fix.

The upstream [smbpasswd manual](https://www.samba.org/samba/docs/current/man-html/smbpasswd.8.html)
and [pinned source](https://github.com/samba-team/samba/blob/samba-4.22.11/source3/passdb/passdb.c)
are the reference, not assumptions based on command names or exit status.

`smb_disabled_password_qemu_linux.go` characterizes those paths on a disposable
ARMv5 guest and the running loopback-only Samba daemon. It uses a newly reserved
test account, proves initial login, explicit disable, unchanged credential after
combined `-s -d`, and re-enabled login after ordinary password rotation. It then
disables the account again and removes its test passdb entry. Authentication is
tested through IPC$, without granting access to data shares. Unix account files
and configuration must stay identical. The marker is explicitly a **boundary**,
not an approval of the unsafe sequence; it must be reviewed after Samba upgrades.

Never treat a subsequent disable, daemon restart, or successful CLI exit as proof
that no enabled interval occurred. Do not use `pdbedit --set-nt-hash` as a shortcut:
password-equivalent material in process arguments is outside the secret boundary.
No NT/LM hash, password or passdb dump belongs in a journal, log, response or wiki.

## Selected implementation direction, not yet qualified

Use Samba's existing password/SAM machinery, not a new implementation of SMB
cryptography or direct TDB editing. Implement a narrow, root-only, fixed-config
adapter that requests `LOCAL_SET_PASSWORD | LOCAL_DISABLE_USER` for an existing
managed identity in one `local_password_change` call. A small maintained upstream
CLI extension or an in-tree helper is the candidate; the current CLI cannot
express that combination. This choice still needs compiled implementation,
source/ABI/license review and actual ARMv5 failure tests. No downstream Samba
patch is installed by this increment.

The inspected function orders password changes and the disabled flag before its
SAM update, making this a promising boundary, **not proof of cross-database or
power-fail atomicity**. Qualify the selected tdbsam backend, password history,
SID/RID ownership, durable state and multi-process serialization independently.
An already enabled account must not silently enter this path: the product owner
must first complete explicit disable/revocation according to its policy.

## Required owner workflow

1. Hold the single identity authority; validate immutable account/name/UID/GID,
   native creation confirmation, exact qualified passdb/config and Unix binding.
   Reject adoption of an unrelated existing Samba entry, including SID/RID clashes.
2. Journal an intent before each passdb mutation. For initial enrollment, create
   a disabled account without a usable password and verify that binding. No
   automatic retry of ambiguous creation or password replacement.
3. Receive a bounded secret through protected memory/stdin only. Validate its
   encoding/length and refuse protocol separators; do not persist it for recovery.
   Set the password while retaining disabled state in the same SAM update and
   confirm the resulting metadata. A password-change timestamp alone does not
   prove the intended secret was applied.
4. Persist `credential-set-disabled`. Enabling is a separate explicitly
   authorized, revision-checked operation with its own durable intent and result.
   The panel must distinguish desired state, observed state and review-required
   uncertainty rather than display unconfirmed enabled/disabled claims.
5. On failure or interruption, retain intent/evidence and deny automatic service
   activation until reconciliation. Never reset the ledger, recycle identity IDs,
   delete an ambiguous account, or store/replay its password to make tests pass.
6. Keep share grants and account enablement coordinated. Disabling a passdb entry
   was tested only for **new connections**; revocation of authenticated sessions,
   open files and durable handles requires separate implementation/qualification.

## Acceptance tests before panel wiring

- New disabled enrollment never authenticates before explicit enable.
- Replacing a disabled password never authenticates during or after the update;
  after explicit enable only the replacement succeeds.
- Existing unrelated accounts, SIDs, data ownership and permissions are unchanged.
- Wrong account/revision/config, unsafe paths, duplicate identity, full/read-only
  state, command failure, cancellation and interruption preserve evidence and do
  not publish a false successful state or invoke an automatic retry.
- Restart/reboot reconciles confirmed and ambiguous operations without a stored
  plaintext password. Crash/power-loss guarantees match actual storage evidence.
- Commands, diagnostics, journals, HTTP/UI, process arguments and repository
  artifacts do not disclose passwords or password-equivalent hashes.
- All of this passes with actual ARMv5 Samba and the eventual qualified EX4
  storage layout; host models alone are insufficient.
