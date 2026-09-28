# Internal Samba account enrollment journal

This Linux-only library coordinates the first enrollment of one owner-created,
disabled Unix identity into Samba. `identityowner` is the required parent: it
holds the authority lifetime lease and the same non-queuing lock used by Unix
identity creation for every Samba observation, journal transition and mutation.
This is an in-process contract, not an HTTP/RPC endpoint or a complete account
manager.

## Contract implemented

The initial enrollment is revisioned and follows only this path:

```text
reserved
  -> create-disabled-intent
  -> disabled-no-password
  -> set-password-disabled-intent
  -> credential-set-disabled
```

The backend must first report the exact passdb identity absent. An existing
entry is never adopted. Before a mutation, the owner revalidates the matching
Unix identity and the operation compares the exact account/revision. Creation
and password setting each have a durable intent before their native command;
the resulting passdb SID and disabled state must be observed before confirmation.

An interrupted intent, command error, lost response or uncertain post-command
observation becomes `review-required`. Reopening through `identityowner` makes
that transition without querying or rerunning the command. It has no reset,
retry, delete, enable, replacement, disable or retirement operation. Reaching
`credential-set-disabled` does not enable access; a separately designed and
authorized lifecycle is required for that.

The journal stores only the owner-bound Unix account, native journal revision,
Samba SID, phase and revision. It never stores password bytes, NT/LM hashes,
command output or password-derived material. Password input is bounded to
12–256 UTF-8 bytes, rejects control characters, and is handed to the trusted
backend in memory for stdin transport. The owner and backend must not log it.

## State layout and API

After enrollment is first attempted, the per-account owner directory contains:

```text
authority/operations/<validated-account-id>/smb/
  smb-operation.json
  .smb-operation.pending   # only during an atomic durable update
```

`Store` is a single-operation journal and does not own the global identity lock.
Only call it through `identityowner.Owner.SMB(id)`, whose `Begin`, `Step`,
`SetPasswordDisabled` and `Load` hold the shared authority lock. The trusted
adapter is bound once when the owner opens and copied into each journal handle
at `smbprovision.Open`; no operation accepts a replacement backend. Opening
without one permits recovery/inspection but fails closed for mutations. The ID
is resolved against the owner ledger before path construction. The separate
`identityrpc` version-2 local channel transports these typed Owner operations
only in the disposable QEMU fixture. No HTTP method or production listener
startup is supplied here.

## Qualification and limits

The fixed Linux passdb executor is implemented in the sibling
[`smbexec` package](../smbexec/README.md). The ARMv5 QEMU fixture exercises that
same executor against a disposable account and private `smb.conf`; fixture
configuration and test wiring are not production startup code. This does not
qualify the real EX4 Samba state location/passdb backend, concurrent
non-cooperating root writers, tdbsam crash durability, password history,
session revocation or hardware power-loss behavior.

Tests cover strict journal decoding, password/journal separation, disabled-state
confirmation, no adoption, shared owner locking, changed Unix identities,
process exit after command intent and recovery without command replay. Full
product integration still needs to bind the executor and local channel to an
approved persistent Samba configuration during service startup, HTTP
policy/authorization and the separate explicit enable/disable lifecycle.
