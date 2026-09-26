# Journaled native Unix identity creation

This coordinator connects an existing disabled service-account reservation to
two typed backend actions: create its private group, then create its Unix user.
It does not create reservations, passwords or homes, activate Samba/NFS, import
legacy users or expose HTTP. The separate Linux
[typed executor](../identityexec/README.md) now supplies the restricted BusyBox
backend in the guarded QEMU scenario; production privilege ownership/transport
is not yet implemented.

One caller-provisioned private directory owns one operation. The Linux store
reuses the exclusive-lock, fixed-name, fsync/rename revision engine; its public
methods are Begin, Step, Load and Close, never arbitrary Commit/reset/delete.
The strict 4 KiB JSON journal binds the exact disabled account and reservation
revision. Phase and operation revision must match; no credentials are recorded.

| Durable phase | Next behavior |
| --- | --- |
| reserved (1) | Require fresh complete absence; commit group-intent before one group command |
| group-intent (2) | Resumed intent is ambiguous: move to review-required; never replay |
| group-confirmed (3) | Require the exact group only; commit user-intent before one user command |
| user-intent (4) | Resumed intent is ambiguous: move to review-required; never replay |
| unix-confirmed (5) | Recheck the exact user/private group; run no creation command |
| review-required | Terminal in this API; no automatic repair, adoption, cleanup or reset |

After a successful command the backend must provide a fresh matching
observation before confirmation can commit. Command errors, cancellation after
dispatch, partial/conflicting results or failed post-command observations demand
review. A confirmation-write failure retains an intent or an uncertain storage
outcome: close/reopen/reconcile, never retry the command automatically. A failed
pre-command observation runs no command and does not erase the last phase.
An already existing exact account is refused by Begin, not silently adopted.
Even complete absence after an interrupted intent is not retry permission.

The caller must own a qualified state location and serialize **all** registry,
Unix and identity-authority writers across each operation. This operation's
directory lock does not lock `/etc` or the separate registry. The supplied
registry must remain the exact revision, and observations must come from trusted
coherent sources. The backend is trusted in-process code, not remote input;
it must independently validate and supervise fixed bounded commands. No
network-facing adapter is supplied; the backend interface has no arbitrary
executable/argument or shell-command method.
Production global ownership, durable Unix layout and privileged transport are
still unimplemented. A result is not an authorization lease.

Unix-confirmed checks identity, **not** a locked login, shell policy, Samba
passdb state, password validity, service activation or effective permissions.
No rollback deletes an account or its files. Recovery decisions for partial or
uncertain operations, and protected journal retention/anti-rollback, remain work.
Do not replace review-required records manually to bypass these boundaries.

Linux tests use private temporary files and modeled backends, including real
child-process exits immediately after durable intent, concurrent stale callers,
command/observation failures, cancellation and obstructed pre/post-command
commits. Fixtures explicitly provision 0700 storage; permissive temporary
directories must remain refused. Journal parsing has a bounded fuzz lane.

The existing ARMv5 QEMU temporary-account scenario uses this coordinator with a
fixed machine/disk/account-guarded wrapper around the typed executor. It creates a real group, closes and
reopens the confirmed journal, then creates the real no-login/no-home user and
verifies the completed journal, locked Unix login, nologin shell and no home
creation. Its separate fixture cleanup still checks
absence after removing the disposable account; cleanup is not a coordinator API.
Host process-interruption tests are not physical power-loss qualification.
