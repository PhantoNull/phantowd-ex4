# Internal Samba account enrollment journal

This Linux-only library coordinates first enrollment and separate explicit
enablement of one owner-created Unix identity in Samba. `identityowner` is the
required parent: it
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
  -> enable-intent
  -> enabled
```

The backend must first report the exact passdb identity absent. An existing
entry is never adopted. Before a mutation, the owner revalidates the matching
Unix identity and the operation compares the exact account/revision. Creation
and password setting each have a durable intent before their native command;
the resulting passdb SID and disabled state must be observed before confirmation.

Enabling is a distinct revision-checked call accepted only from
`credential-set-disabled`. It verifies the exact account, SID and disabled
state, commits `enable-intent`, invokes the fixed trusted executor, then confirms
the same SID is present and enabled before recording `enabled`. Account creation
and password assignment never enable as a side effect. An interrupted intent,
command error, lost response or uncertain post-command observation becomes
`review-required`; reopening through `identityowner` quarantines it without
querying or rerunning the command. There is no automatic retry, reset, delete,
replacement, disable or retirement operation.

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
`SetPasswordDisabled`, `Enable` and `Load` hold the shared authority lock. The
trusted
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
in-flight transfer/open-handle/durable-reconnect behavior or hardware
power-loss behavior. The local QEMU fixture does exercise account-scoped
session revocation for `Disable`; it is not yet product startup/runtime
integration.

Tests cover strict journal decoding, password/journal separation, disabled-state
confirmation, explicit enable/revision checks, same-SID postcondition,
no-adoption, shared owner locking, changed Unix identities, process exit after
create/password/enable intent and recovery without command replay. QEMU verifies
authentication is denied before explicit enable, accepted afterward with the
new credential and still denied for an empty password. `Disable` also denies
new logins, requests one account-scoped logoff and confirms no target sessions
remain; an unrelated account from the same client IP remains usable. This is
fixture-only: product integration still needs persistent Samba
configuration/startup, HTTP-session authorization and operator review handling;
retirement, in-flight transfer/open-handle behavior and durable reconnect
remain unqualified.
