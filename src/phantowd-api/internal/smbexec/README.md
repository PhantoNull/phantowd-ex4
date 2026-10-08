# Internal trusted Samba passdb executor

This Linux-only internal package implements the fixed command adapter for
M2.4 enrollment/credential transitions and M2.5 account-scoped disable plus
session revocation. It is not a service, HTTP/RPC endpoint, or account manager. The caller must be the root-side
`identityowner.Owner`; it binds one
executor when the owner opens and holds the existing owner lock around every
observation, journal transition, and mutation.

## Command boundary

- The base command adapter fences all operations before its first configuration
  close attempt. A failed close retains the first error and the original object
  reference: subsequent `Close` calls never retry or report success, and even an
  empty observation is refused after closure. This does not prove that an
  errored descriptor remains open. Real regular-file closure and concurrent
  observation regressions cover the base adapter; they do not qualify kernel
  EIO, the separate tagged native wrapper or durable product recovery.
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
  A runner's successful exit/output after the status child deadline is also
  refused: output is cleared and no further inventory or control is dispatched,
  even when the caller's parent context is still live.

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

### Native retained runtime fixture

`NativeBackendQEMU` is compile-tagged and bound once to a guarded private
runtime. The factory pins the original configuration inode; successful
construction transfers runtime teardown responsibility to the backend, while
failure leaves teardown with the trusted fixture caller. Existing command and
observation logic maps only to fixed typed worker verbs and two fixture users.
No call accepts a replacement backend or caller-selected executable/config.

The actual ARMv5 fixture now enrolls both Owner-created Unix identities through
`identityowner.OpenWithSMBBackend`: disabled-first creation, sealed stdin-only
password, still-disabled confirmation and separate same-SID enable. Code,
original config and original mutable-state tuples remain retained through
verified worker settlement/close; the normal-cycle final FD count is unchanged.

The native adapter now fences all operations before its first Close attempt.
Runtime or inner-configuration close uncertainty retains the first error and
review without retry; later Close cannot report success or touch replacements.
The original inner bookkeeping stays retained after its close fails, which is
not proof that the errored descriptor remains open. A private fixed
`closeInnerAfterRuntimeQEMU` step is called only after independently verified
runtime closure and accepts no alternate closer/runtime/backend. Real-file host
regressions reach that post-runtime step, then exercise repeated public Close,
concurrent observations and replacement noninterference. They qualify the
inner-close bookkeeping, not runtime retirement, kernel EIO or actual guest
fault recovery. Normal guest qualification must match the changed source.
The same-state daemon now has focused actual ARMv5 authentication and active
session-revocation proof: two fixed held clients, complete qualified inventory,
one target-only logoff, two complete absence inventories, the SAME peer session
and process generation, denied new target login and unaffected peer login.
The witness is private, backend-bound and nonserializable; empty, incomplete,
foreign or replaced evidence is refused. Whole client/daemon groups settle
before original pins close; final FD equality and unchanged base are mandatory.

Complete native worker admissions require a separate fixed timing profile:
status4/control4/aggregate20 seconds, while ordinary commands retain
status2/control-at-most5/aggregate5. The aggregate native verification budget
covers one initial inventory, one control and two stable-absence inventories,
plus one worker-sized margin for bounded parsing/polling. Unknown profiles
refuse before effects, and shorter caller deadlines always win. No request can
select a duration, backend or executable. The earlier total10-second native
profile truncates its final inventory when four measured workers each take
about2.6 seconds; the independently capped control cannot consume the entire
new aggregate budget. This fixture-only adjustment is not an EX4 performance
specification or a product deadline change. All complete admissions remain.
The controller retains separate startup20/idle20/session45-second phases, with enrollment60 and guest180
unchanged. Ordinary non-root Linux timing tests cover the complete composite
sequence and uncertain-control/no-retry path; constructor ownership and actual
wrapper binding retain separate root/ARMv5 tests. Host/race tests enforce both
profiles and shorter caller deadlines.
Full-image/hosted qualification, in-flight/durable handle semantics, sustained
supervision, continuous identity/storage authority, fault/recovery and product
ownership composition remain unfinished. This is not physical EX4 evidence.

### Identity-bound native startup and supervision (QEMU only)

`NewNativeIdentityServiceQEMU` takes the existing identity Owner, an expected
complete fingerprint and its exact startup-fixed `NativeBackendQEMU`. It takes
the runtime only from that backend, never from a second caller-supplied runtime.
The guarded runtime must be pre-daemon/pre-client with no pending worker;
complete checks bracket acquisition of a backend-bound identity consumer.
The original coordinator pointer must not be copied. Trusted callers transfer
its lifecycle control and must not operate backend/runtime aliases concurrently.

`Start` is single-use and freshly verifies identity on both sides of actual
daemon startup. Verification is outside the runtime gate: the Owner's complete
passdb observations already call that runtime through the fixed backend.
`Observe` rechecks complete registry/journal/Unix/passdb evidence and the SAME
code/config/state/daemon through those retained workers. `Supervise` owns one
exclusive loop, with fixed idle intervals of 1 second to 1 hour, no catch-up,
competing-operation refusal, and no restart. Accepted cancellation stops the
daemon/client set, keeps the identity reference and requires explicit `Close`.
Atomic `Status` returns only immutable redacted telemetry during that loop;
it never authorizes a service, grants a lease or exposes account identifiers.

Complete runtime closure must succeed before identity `Release`. Uncertain
startup/stop/close keeps review and the consumer; repeated `Close` cannot turn
an earlier runtime error into success. A pending credential capture cannot be
hidden by successful daemon stop. Late uncertain construction returns both a
quarantined handle and an error; keep that handle rather than substituting a
new consumer. No automatic recovery or arbitrary fingerprint refresh exists.

The focused actual ARMv5 positive trace qualifies pre-/post-start Owner close
refusal, canceled/duplicate startup refusal, complete manual and timed scans,
serialized observations, accepted cancellation after a completed scan,
retention after stop, full closure before release and final FD equality. All
older authentication/revocation/isolation markers remain mandatory. Its new
40-second phase follows the unchanged legacy experiment in the SAME native
guest; enrollment60/startup20/idle20/preparation20/live45/guest180 limits are
unchanged. The driver now has 40 tests plus seven loader tests.

Frozen `e445f1c` also passes the complete cached local Buildroot lane, including
the standard smoke, two-boot state and synthetic SMART lanes. All 887 tracked
API source files match the compiled package and legal-info archive; installed,
image-contained and exported API bytes agree, and seven artifact hashes verify.
This does not establish independent clean, hosted, hardware or release safety.

This first trace is **normal lifecycle only**. Real identity/code/state drift,
unexpected daemon exit, mid-worker cancellation and uncertain stop/close still
need coordinator-specific disposable-subprocess QEMU fault proofs. The subsequent
explicit coordinator Disable trace below composes the separate verified
successor; unapproved mutations outside it still invalidate its consumer.
Storage/grants, continuously retained
bootstrap provenance, product authorization/startup and durable recovery remain
open. No HTTP endpoint, product listener or physical NAS operation is added.

The subsequent focused trace qualifies one **state-directory alias replacement**
in guest tmpfs. Valid original descriptors survive capture construction; complete
runtime admission refuses the changed alias before execution. Daemon/client
groups stop, but the unconsumed pending capture and code/config/state/identity
authority remain retained in review. Restoring the original alias cannot revive
the service or turn repeated uncertain Close into success. A read-only fixture
observation verifies stopped owned groups, capture settlement and retained
inputs; settlement alone does not prove a capture never ran. The child exits
only after these witnesses pass. Parent FD equality is mandatory; child process
disposal is not product recovery. Clients were not held active in this trace.

Invalid modes instead refuse capture construction before pending installation;
that earlier branch must not be presented as the same fault. Final local proof
passes 42 driver/seven loader tests and three fresh campaigns using one compiled
image: service access/lifetimes, native credentials/live revocation, and native
startup/supervision/faults. Each guest remains bounded to 180 seconds. Enrollment,
authentication and idle-disable preparation execute on fresh state in both native
campaigns. All original guards, phase ordering, equal code census and base hashes
remain mandatory; there is no cross-guest authority or automatic retry. Broader
fault and product gates above remain open, as does new whole-image qualification.

### Explicit Disable through the retained coordinator (QEMU only)

`Disable(ctx, id, revision)` is serialized with startup, observation, supervision
and close. It uses only the SAME Owner's fixed backend and retained consumer.
The verified atomic successor replaces that consumer without a zero-reference
gap or reviving the old token. A qualified pre-intent revision conflict returns
unchanged; other uncertainty retains review and stops without mutation retry.
Prepared/stopped coordinators refuse. The exclusive supervisor refuses mutation
while running; a product command loop is a separate unqualified contract.

The actual ARMv5 trace holds two distinct sessions through fixed coordinator
helpers, refuses canceled/stale requests, confirms the unchanged journal after
refusal, then requires the same-SID disabled journal and exact original peer
session/server generation. New target login is denied; peer login still works.
Owner Close stays busy until complete runtime closure. All42/seven tests, three
campaigns, prior fault/privilege guards, FD counts and base hashes pass, together
with root native race-count3/tagged vet and Windows API/UI/cross-compilation.
The added live phase is bounded to45 seconds; post-transition observation/stop
has20 seconds, independently of startup40 and the unchanged guest180/worker4/
revocation10 limits. The fault child explicitly re-enables the synthetic target
before NEW admission, never by refreshing a consumer or fabricating passdb.

This is not product activation, storage/grant or continuous-bootstrap authority,
complete cached/clean/hosted qualification, durable recovery or EX4 evidence.

### Planned service and fixed data access (QEMU only)

`NativePlannedServiceQEMU` retains the SAME identity Owner/startup backend,
complete mounted roster and original share pins. Trusted callers transfer
lifecycle control; they must not concurrently operate runtime/backend aliases.
Fresh complete planning is outside the runtime gate, under storage-first
ordering. Uncertainty retains review; verified runtime closure precedes release
of either original authority, and uncertain closure is never retried.

Its single-use `VerifyDataAccess` exercises six fixed clients through the SAME
already-running service. It accepts no alternate runtime, root, credential,
command or backend. Cancel/busy/unstarted/repeated operations refuse; complete
authority observations bracket the probe. `DataVerified` is historical proof
completion, not health or permission to activate a product service. Host/race
and four real ARMv5 snapshots qualify normal access at `e3e1d5b`, not full
UNC/mixed ACL, constructor/late-close faults, continuous supervision, changed
whole-image audit, hosted/clean or EX4 behavior. See
[implementation status](../../../../IMPLEMENTATION-STATUS.md).

`Supervise(ctx, interval)` now owns the composed lifecycle exclusively while
performing serial complete storage-first/identity scans at a fixed idle interval
of 1 second to 1 hour. It accepts no replacement authority, runtime or backend.
Competing observations/start/access/close and a second loop refuse; there are
no catch-up scans or automatic restarts. Accepted idle cancellation verifies
daemon/client stop but retains BOTH original identity and share authorities
until a separate successful full runtime `Close`. Failed scans or uncertain
stop/close preserve review, retained authority and refusal of uncertainty retry.
Immutable `Status` is telemetry only, never admission or recovery evidence.

On 2026-10-08, tagged Linux tests, seven-package race-count3, ARMv5 cross-build,
62 Linux verifier tests and all six independently enrolled ARMv5 campaigns pass.
The actual data guest keeps the SAME service through original startup/access,
a complete timed scan, exclusive refusals, idle cancellation, stopped-authority
retention, restart refusal and full-close-before-release/FD equality. Its new
proof is mandatory exactly once in data; all old proof bytes/order and deadlines
remain. The supervised action has its own 20-second fixture budget, not leftover
startup/data time. This qualifies only the normal composed supervision path.
Composed drift/exit/mid-worker/uncertain stop/late-close proofs and a new complete
source/image audit remain open; previous identity-only fault proofs do not
qualify this coordinator. No HTTP, product activation or physical NAS operation.

A post-run negative-only Close/Status regression preserves review telemetry
when a prior close error prohibits cleanup retry. Invalid runtime admission
cannot start or own a process; this does not qualify live uncertain teardown.
