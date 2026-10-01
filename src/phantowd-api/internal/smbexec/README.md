# Internal trusted Samba passdb executor

This Linux-only internal package implements the fixed command adapter for
M2.4 enrollment/credential transitions and M2.5 account-scoped disable plus
session revocation. It is not a service, HTTP/RPC endpoint, or account manager. The caller must be the root-side
`identityowner.Owner`; it binds one
executor when the owner opens and holds the existing owner lock around every
observation, journal transition, and mutation.

## Command boundary

- Executables are fixed absolute paths: `/usr/bin/testparm`,
  `/usr/bin/pdbedit`, `/usr/bin/smbpasswd`, `/usr/bin/smbstatus` and
  `/usr/bin/smbcontrol`.
- The startup-supplied Samba configuration path is not request data. It must be
  absolute, non-symlinked, a root-owned regular file, not group/other writable,
  and no larger than 1 MiB. The child receives it through an inherited file
  descriptor (`/proc/self/fd/3`), not a client-selected path. The executor pins
  that opened inode until `Owner.Close`; later replacement of the path cannot
  retarget an operation. Before returning a backend, `New` runs `testparm -s`
  against that same descriptor with a five-second deadline and fixed
  environment. Missing or semantically invalid configuration, or an unavailable
  validator, fails closed before the backend can be bound to an Owner. The
  `Owner` takes ownership of the executor at open and closes it after operations
  drain, or immediately if open fails.
- Child environments are restricted to fixed `PATH` and `LC_ALL=C`. Validation
  has a five-second deadline; account commands have a ten-second deadline;
  observation output is capped at 1 MiB. Mutation output and stderr are
  discarded, and errors are redacted.
- `Observe` lists passdb metadata with `pdbedit -L -v -s`, then returns only the
  exact requested Unix name, owner-supplied UID/GID, SID, and disabled bit.
  Missing or ambiguous/malformed target records fail closed. Password hashes
  and the full command output are not exposed.
- `ObserveAccounts` serves the internal Owner evidence snapshot with one
  bounded listing for up to the live-account limit, returns rows in request
  order, and clears captured output before returning. It refuses duplicate
  requests, repeated target names/SIDs, and case-variant matches rather than
  treating them as an absent account. Any malformed requested row fails the
  whole batch; unrelated rows and their authentication material are discarded.
- `CreateDisabled` invokes `smbpasswd -a -d` with no password input. The parent
  journal verifies that the new entry is present and disabled before recording
  confirmation.
- `SetPasswordDisabled` invokes the pinned
  `smbpasswd -s --set-password-disabled` extension. Password bytes are sent
  only as the two expected stdin lines; they are absent from argv, environment,
  diagnostics, and the journal. The parent verifies the same SID remains
  disabled before recording success.
- `Enable` invokes the fixed `smbpasswd -e` command with no password payload.
  The parent journals a separate revision-checked intent, requires the exact
  SID/account to be disabled before dispatch, and confirms that same SID is
  enabled before recording success. It is never called implicitly by create or
  password assignment.
- `Disable` first invokes `smbpasswd -d`, then parses the complete pinned
  Samba `smbstatus -j` session inventory. If the target Unix account still has
  sessions, one account-scoped `smbcontrol smbd logoff-user <name>` is sent;
  no PID-only or client-IP-wide termination is used. Success requires two
  consecutive complete inventories with no target sessions, at least 100 ms
  apart and within a five-second revocation deadline. The parser rejects
  malformed/ambiguous session records instead of treating them as absence.
  Status reads may repeat for verification; the disable mutation and logoff
  control are each sent at most once. A command error, malformed inventory,
  cancellation or timeout is returned as an uncertain failure so the journal
  moves to `review-required` and will not replay it. Revoking a live SMB session
  can interrupt transfers or writes in progress.

The executor does not create Unix accounts, automatically enable Samba
accounts, implement retirement, repair pre-existing state, retry an uncertain
command, or serve client protocols. A missing reply or uncertain result remains
a `review-required` operation under `smbprovision`.

## Verification and remaining integration

Root-run Go/race tests exercise fixed arguments, exact-record and batched
parsing,
configuration ownership/mode/syntax checks and path-replacement resistance,
stdin-only secret delivery, output clearing, and redacted failures. Tests verify
that missing configuration creates no files and invalid configuration remains
unchanged. The ARMv5 QEMU fixture runs
this same executor against a disposable Samba passdb and private test
configuration. It verifies disabled-first enrollment, same-SID enable, and
disable that denies new logins, disconnects only the target account's active
sessions, verifies their absence, and leaves another account from the same IP
usable. Stale process generations are rejected by the pinned Samba message
receiver guard. This does not qualify the real EX4 Samba configuration/passdb
location, concurrent non-cooperating root writers, in-flight write/handle or
durable-reconnect semantics, power-loss durability, or an installed firmware
service.

The executor is not wired to product service startup. Before that, the project
must choose and provision the persistent Samba configuration/passdb paths,
define ownership and startup ordering, connect the fixture-only internal v2
channel to product startup and HTTP authorization, and define operator handling
for review-required state. No HTTP credential endpoint exists in this slice;
enablement is explicit in the internal/QEMU path and never automatic.
