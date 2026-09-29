# SMB credential lifecycle: integration gate

Status: **M2.3 adapter passed exact-head hosted ARMv5 QEMU and Stage B3 checks
and merged as PR #46 (`33df1ed`). M2.4 now includes first enrollment,
password assignment while disabled, separate journaled enable/disable/re-enable,
a fixed Linux Samba executor and an internal credential-bearing Unix-socket v2
fixture. Host/race/fuzz checks and the full local Buildroot/ARMv5 QEMU smoke
and two-boot checks pass on this worktree. M2.5 now extends the same journaled
`Disable` operation to log off that account's active SMB sessions and verify
their absence. These are local results, not hosted exact-head CI for this
follow-up. The fixture is not a product service and has not qualified
in-flight writes, open-file or durable-reconnect semantics.**
The channel remains a fixture integration only and is not wired to
product startup, an HTTP endpoint or persistent EX4 Samba state. Production
authorization binding, review/recovery and hardware qualification remain open.
Dashboard administrator credentials are separate and are not affected by this
Samba behavior.

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

The `smb_disabled_password_qemu_linux.go` characterization uses a disposable
ARMv5 guest and loopback-only Samba daemon. It demonstrated that the old CLI
cannot safely express the requested transition. The new fixture requires the
downstream option and checks actual authentication for the intended state
transition. It passed against patched ARMv5 Samba in a local full Buildroot
2025.02.18 / Linux 6.18.53 build, including the root-only and stdin guards,
denial of the previous credential after explicit enable, and unchanged Unix
account files. One fixture expectation was corrected: Samba returns generic
`NT_STATUS_LOGON_FAILURE` for a wrong password even when the account is disabled;
the test now checks `NT_STATUS_ACCOUNT_DISABLED` only with the valid credential.
This local result is not hosted exact-head CI, crash/power-loss evidence,
product-state persistence or EX4 hardware qualification. Re-review the boundary
after every Samba upgrade. The exact feature commit `8866614` passed hosted
[ARMv5 QEMU run 36461848337](https://github.com/PhantoNull/phantowd-ex4/actions/runs/36461848337)
and [Stage B3 run 36461848317](https://github.com/PhantoNull/phantowd-ex4/actions/runs/36461848317),
then merged to `develop` as `33df1ed`. These checks validate the fixture/build
boundary, not a product credential service or EX4 storage/hardware behavior.

Never treat a subsequent disable, daemon restart, or successful CLI exit as proof
that no enabled interval occurred. Do not use `pdbedit --set-nt-hash` as a shortcut:
password-equivalent material in process arguments is outside the secret boundary.
No NT/LM hash, password or passdb dump belongs in a journal, log, response or wiki.

## Selected adapter prototype; qualification pending

Use Samba's existing password/SAM machinery, not a new implementation of SMB
cryptography or direct TDB editing. The selected prototype is a narrow
`smbpasswd --set-password-disabled` extension, maintained as a versioned
Buildroot patch under `board/qemu/armv5/patches/samba4/4.22.11/`. It is root-only,
requires `-s` so the new password is read from stdin, and requires one explicit
local username. It rejects incompatible account operations and only accepts an
already-existing, already-disabled passdb account. The adapter requests
`LOCAL_SET_PASSWORD | LOCAL_DISABLE_USER | LOCAL_REQUIRE_DISABLED`; the common
password-change path validates the initial state, applies both changes to the
same SAM object and reaches one final `pdb_update_sam_account` call.

The exact Samba 4.22.11 source archive/hash was verified, the patch applies with
zero fuzz, a native Samba configure/build completed locally, and the patched
ARMv5/QEMU authentication fixture passed both locally and on exact-head hosted
CI. Failure and restart cases, persistence, tdbsam/password-history, SID/RID
binding and single-writer behavior remain open. This is not a product credential
service or deployed firmware feature. The patch is GPL-3.0-or-later derivative
work and is not installed on the NAS.

The source path reaching one SAM update is **not proof of cross-database,
concurrent-writer or power-fail atomicity**. Qualify the selected tdbsam backend,
password history, SID/RID ownership, durable state and multi-process
serialization independently. An already enabled account must not silently enter
this path: the product owner must first complete explicit disable/revocation
according to its policy. A separate identity owner must serialize all writers;
the CLI flag is not itself a global lock or journal.

## M2.4 journaled SMB account lifecycle

The journaled account-lifecycle slice now lives in the internal `smbprovision`
package and is reachable only through in-process `identityowner.Owner.SMB(id)`
methods. The owner takes
its existing global lock across live Unix-identity revalidation, passdb
observation, journal commits and each backend command. An entry must be absent;
the coordinator never adopts a pre-existing passdb account. It journals intent,
creates the entry disabled without supplying a password, confirms the exact
account/SID and disabled flag, then sets the bounded password through the
backend's stdin-only contract and confirms the same SID is still disabled. A
separate revision-checked `Enable` operation accepts only a confirmed disabled
state: it confirms the same account/SID is disabled, commits `enable-intent`,
invokes fixed `smbpasswd -e`, then confirms the same SID is enabled before
recording `enabled`. A separate `Disable` accepts only a confirmed enabled
state and commits `disable-intent`, invokes fixed `smbpasswd -d`, then uses
complete `smbstatus -j` observations and one account-scoped
`smbcontrol smbd logoff-user` to close any existing sessions for that Unix
account. It records `disabled` only after the same SID is disabled and two
consecutive inventories show no target sessions. No client-IP-wide or PID-only
termination is used. This may interrupt active transfers/writes. If command or
verification state is uncertain, the durable operation becomes
`review-required`; no disable or logoff mutation is replayed. Re-enable is
another explicit `Enable` action. Creation, password assignment, enable and
disable never happen as implicit side effects.

The journal contains no password, NT/LM hash, command output or derived secret.
It has no automatic retry, reset or retirement operation. Password assignment
may replace credentials only while the account is confirmed disabled. After
reopening, a durable create/password/enable/disable intent is committed to
`review-required` without querying or rerunning Samba. The trusted backend is
bound once at Owner open; individual operations cannot replace it. The existing
credential-free JSON v1 identity protocol remains unchanged. The separately
versioned internal binary v2 socket carries a bounded password only as raw
bytes for `set-password-disabled`; distinct `enable` and `disable` actions carry
no password and reach the bound Owner operation. It returns the same restricted,
secret-free state vocabulary and does not expose an HTTP endpoint. QEMU uses
the protected socket only with its disposable fixture account and verifies the
valid credential fails before enable and works after same-SID confirmation.
Production listener/startup wiring and HTTP-session authorization binding
remain unimplemented.

Local verification on 2026-09-28 passed root-run `go vet`, all API Go tests and
race tests, the fixed-count journal fuzz lane, and the full Buildroot 2025.02.18
/ Linux 6.18.53 ARMv5 QEMU build and smoke. QEMU exercises the same fixed Linux
`internal/smbexec` executor used for trusted runtime integration, but only with
one disposable fixture account and private `smb.conf`; it proves empty
credentials fail and the new valid credential remains denied while disabled.
The 2026-09-29 follow-up pins the validated configuration inode for the Owner
lifetime, rejects pathname replacement as a retargeting mechanism, and verifies
single-close lifecycle behavior. Root-run vet/race tests and a full local
Buildroot ARMv5 QEMU smoke/two-boot rerun passed. The executor is not yet wired
to product startup or persistent Samba configuration. The 2026-09-29 internal
credential-channel follow-up passed the Windows API suite/cross-compilation,
root Linux `go vet` and full API race suite, then the full Buildroot 2025.02.18 /
Linux 6.18.53 ARMv5 QEMU smoke. Its log records protected-listener
`smb-create` and `smb-password` phases and the
`PHANTOWD_SMB_DISABLED_ENROLLMENT_READY` check; fixed-count fuzz lanes also
passed. The current lifecycle follow-up adds Owner, journal, executor and
version-2 channel enable/disable actions; it verifies stale revisions do not
dispatch, same-SID state confirmation, valid credential denial before enable,
successful authentication after enable, denial of new authentication after
disable and successful authentication after re-enable. The full local Buildroot
2025.02.18 / Linux 6.18.53 ARMv5 QEMU build/smoke and two-boot suite passed on
2026-09-29, along with API/tool-host tests, race tests and fixed-count fuzz
campaigns. M2.5 additionally tests two live target sessions and an unrelated
same-IP peer: `Disable` sends one account-scoped logoff, verifies target-session
absence, rejects a fresh login and leaves the peer able to read. A stale
process-generation control is also proven not to affect that peer. The full
local ARMv5 QEMU build/smoke passed on 2026-09-29. This does not qualify real
EX4 state placement, tdbsam crash/power-loss durability, password history,
other root writers, in-flight write/open-handle/durable-reconnect behavior or
hardware behavior.

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
4. Persist `credential-set-disabled`. Enabling and disabling are separate
   explicitly authorized, revision-checked operations with their own durable
   intent and result. Internal Owner/QEMU paths implement these transitions,
   but product HTTP authorization is not wired. The panel must distinguish desired
   state, observed state and review-required uncertainty rather than display
   unconfirmed enabled/disabled claims.
5. On failure or interruption, retain intent/evidence and deny automatic service
   activation until reconciliation. Never reset the ledger, recycle identity IDs,
   delete an ambiguous account, or store/replay its password to make tests pass.
6. Keep share grants and account enablement coordinated. The QEMU-only M2.5
   `Disable` closes sessions for the target account; this can interrupt active
   transfers/writes. Product deployment still needs authorization and recovery
   UX, while open-file and durable-reconnect semantics require qualification.

## Acceptance tests before panel wiring

- New disabled enrollment never authenticates before explicit enable; after the
  journal confirms the same account/SID enabled, its new password works and an
  empty password remains denied.
- Disable blocks new connections and, in the same journaled operation, revokes
  existing sessions for the target account. Verify two complete absent-session
  inventories, preserve an unrelated same-IP peer, and confirm a separate
  re-enable restores the same credential. Any command or verification
  uncertainty enters `review-required` without retry. Test and document that
  disabling may interrupt transfers; open handles and durable reconnect remain
  unqualified.
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
