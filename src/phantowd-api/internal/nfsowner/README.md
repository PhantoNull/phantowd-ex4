<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors -->

# Experimental NFS lifetime owner

This package exists only with the `qemu` build tag. It implements the approved
host/disposable-QEMU lifecycle and a fixed real-source campaign adapter,
**not a product kernel backend or NFS manager**.
Normal firmware builds cannot construct it. There is no HTTP endpoint or physical
device operation here. The memory-model API executes no command; the separate
Linux/QEMU source join delegates only the fixed finite server fixtures below.

## Fixed inputs and lifecycle

`NewQEMU` captures one valid immutable `Plan.NFSv3TCPCandidate` and one trusted
fixture backend. Missing candidates and nil/typed-nil backends refuse without
effects. Construction performs no I/O: it does not certify exclusive NFSD domain
ownership, retained mount authority or readiness. The caller owns the backend on
construction failure; on success its lifetime belongs to the original handle.

`Start`, `Check`, `Stop` and `Close` serialize complete transitions, refusing
concurrent calls with `ErrBusy`. Copied/zero/nil handles cannot consume the
original lifetime. Operations accept contexts only, not replacement backends,
commands, policies or roots. Formatting is fixed; JSON is refused.

| Transition | Behavior |
| --- | --- |
| Prepared, enabled | Recheck inputs and empty domain; start once; verify readiness; recheck inputs before publishing running |
| Prepared, disabled | Recheck inputs and empty domain; publish disabled without starting/stopping anything |
| Running check | Recheck inputs, readiness and inputs again; failure enters permanent review and attempts one bounded settlement |
| Partial/uncertain startup | Enter review, attempt stop and stopped proof once, retain backend even after successful compensation |
| Explicit running stop | Stop once and verify stopped; retain input references until explicit normal closure |
| Normal close | Settle a running service first; recheck inputs and stopped state before releasing references once |
| Uncertain stop/release | Retain review/backend; no retry, restart, release of remaining references or restoration-based revival |

Pre-admission cancellation has no effects. Admitted callbacks are checked both
before and after execution: late positive results cannot publish success. This
fixture profile has a five-second operation budget and a separate five-second
settlement budget, independent of a canceled request. Backends must honor their
contexts; these cooperative deadlines do not preempt a blocking callback. These
are new experimental limits, not altered existing guest/worker/product timers.

Backend errors are replaced by fixed review errors; only standard cancellation
causes are preserved. `Observe` returns the historical lifecycle state, **not**
a fresh kernel health sample. Backend lifetime retention after a failed release
is not proof that every descriptor remains open: the backend must retain its
original uncertain-close state and never retry recycled descriptors.

## Exclusive supervision

`Supervise(ctx, interval)` holds the original Owner gate for the entire loop;
other operations, including another supervisor, refuse busy. Only running or
configured-disabled lifetimes are admitted. One complete `Check` follows each
fixed idle interval (one second through one hour); the timer is reset only
after completion, so scans neither overlap nor catch up. Existing five-second
check and independent settlement budgets are unchanged. Cooperative deadlines
cannot preempt a blocking backend; polling does not detect every transient fault.

Pre-admission cancellation has no effects. Accepted cancellation while idle
stops a running service with an independent context, retaining inputs until
explicit `Close`. Disabled policy never starts/stops a service. Cancellation
during a check, input/readiness drift or uncertain stop retains review and
authority without retry, automatic restart or release. Normal stopped lifetimes
are not restartable either. Automatic normal/unclean product boot recovery is
still a separate required coordinator, not this loop.

The standard guest source fixture connects this real Owner to original mounted-roster
pins and live identity/storage planning, but its consumer remains a memory
model. Automatic root-replacement detection must stop that model once and
retain pins through restoration; this is not daemon/kernel supervision proof.
No policy-owner/runtime-code authority or effective NFS access is supplied by
the model. Its mandatory receipt explicitly says `kernel_backend=false`.

## Retained export directories (Linux/QEMU only)

`NewExportRootsQEMU` borrows the original complete mounted-roster lease and
compares its verified storage evidence with the immutable candidate. It retains
one volume-root pin per selected volume and independent `O_PATH` descriptors for
each export directory. Whole-volume `.` is supported without reinterpreting it
as an SMB share. Missing paths, symlinks and mount crossings refuse; capture
does not create directories, change permissions or open file contents.

`Check` revalidates the entire original roster, held directory identities and
the same relative paths under the original pins. A replacement directory enters
sticky review even if the original is restored. Ordinary data/ctime changes are
not directory replacement evidence. No descriptor getter or service/data-access
authority is exposed; policy/identity freshness and ACL authorization remain
the containing backend's responsibility. Checks are sequential observations,
not protection against an unobserved replace-and-restore between checks.

The parent lease refuses closure while pins remain. Explicit `Close` requires
the containing consumer to have stopped and closed its copied references; this
leaf cannot prove consumer settlement. It closes owned references once, never
the borrowed lease. Verified disposal does not erase review; uncertain close
retains remaining references without retry. An uncertain constructor rollback
returns an opaque retained-review error that the caller must keep together with
the original containing lease. Complete injected close faults remain unqualified.

External-package native tests cover invalid/disabled/canceled admission and
private handles. The standard ARM fixture verifies two RO/RW-request roots,
whole-volume capture, missing/symlink refusal, parent-close exclusion and sticky
replacement/restoration review using real temporary mounted-volume authority.
It does not start a service or prove effective NFS client access through these
new references. The mandatory receipt says `service=false`.

## Original source/runtime finite fixtures (Linux/QEMU only)

`NewSourceRuntimeQEMU` joins original export-root and complete runtime-input
lifetimes, without descriptor getters or per-operation replacement backends.
Both parents refuse closure. Storage calls finish before runtime gates are
entered, preserving the no-callback lock boundary. Complete immutable candidate
matching is necessary but does not supply a live policy/identity lease.

`NewLeasedSourceRuntimeQEMU` additionally borrows the original NAS-policy and
identity claims plus the original mounted roster at construction. It derives
through `BuildFromLeasedNASOwners`, requires complete candidate equality before
reserving inputs, and repeats that derivation around runtime checks. No runtime
gate is held during storage/identity callbacks. Operations accept no replacement
claims, backend or applied-revision assertion. Released or changed claims refuse;
post-reservation uncertainty preserves the original error/references in review.
The wrapper never acquires/releases the borrowed claims or closes their Owners.
The caller must retain them through verified teardown. These sequential checks
are not atomic admission, continuous in-flight monitoring or complete domain,
state-history/recovery authority; the original unleased constructor remains a
separately limited fixture interface.

The optional source guests use newly provisioned RAM-only policy and identity
Owners with an empty managed-account registry and actual `/etc` census, not
invented UID/GID evidence or a passdb-backed account test. A locked UID/GID1000
fixture is added to a whole-directory RAM copy mounted read-only; the base image
and no-cross-mount census checks remain unchanged. Every source-mode receipt
requires original claims, parent-close fences, released-claim/mismatched-freshness
refusals and unchanged healthy claims before the existing real I/O/fault proof.

`RunAccessFixtureQEMU` delegates one fixed real NFS synthetic-data campaign and
requires normal client/export/kernel/daemon/reference closure before clean join
release. Current names are additionally compared under the original volume with
the original directory tuples; held metadata alone cannot detect replacement.
Observed loss or uncertain validation retains first-cause review and both parents.

The normal source campaign now uses distinct server Start, Check, fixed I/O and
Stop calls. The same original rpcbind/mountd objects, NFSD controller, exports
and private export-table observation survive between calls, without retaining
runtime gates across policy/storage/identity callbacks. The containing join
rechecks its original policy and identity claims around two running observations.
After I/O, exports and daemons remain live until the explicit stop; withdrawal
precedes kernel stop, then mountd and rpcbind stop/reap and reference closure.
Normal cleanup has one independent combined five-second budget; fault campaigns
keep their existing separate profile and budgets. Admitted uncertainty retains
review and originals; complete partial-start/live-fault settlement remains
unqualified. No product boot is enabled.

The normal real-source campaign uses one private fixed backend for the
experimental Owner, with its original candidate, policy/identity claims,
mounted-roster sources and runtime references. `NewServerOwnerFixtureQEMU`
returns only that original Owner, with no backend/path/replacement input,
HTTP or product constructor. Join/root gates cover each backend operation;
runtime gates still return before callbacks enter storage/identity domains.
Fixed synthetic I/O is serialized through `Owner.ExerciseSourceIOFixtureQEMU`.
After service stop, remaining parent closure also requires the same Owner to be
closed; a reviewed or uncertain Owner cannot be discarded by closing its join.

Start and explicit Check use the actual server. Accepted supervisor cancellation
while idle stops it independently of that canceled request; explicit Close then
releases only owned source duplicates, not borrowed authorities. The campaign
witnesses exclusive loop admission before cancellation with a fixed one-hour
idle interval. It therefore proves idle cancellation, NOT periodic real-server
scans. Generic model tests separately cover periodic scans and drift.
The separate policy-loss campaign uses one-second scheduled scans after real
server start/I/O: byte-identical replacement of newly provisioned RAM policy
must trigger actual stop without a manual detection Check. The original file's
replacement is completed outside the watched directory before atomic exchange,
so missing/partial-file detection cannot stand in for identity-loss evidence.
This atomic fault mutation is not atomic service admission. The original file's
restoration cannot revive the Owner or release remaining original claims/input/
source references. The read-only `VerifyServerStoppedRetainedFixtureQEMU` witness
does not retry stop or refresh policy; it requires reviewed original Owner and
actual fixed stopped observations. This one case is not a complete periodic
fault matrix, healthy repeated-scan or client-quiescence qualification.

Stopped verification opens new bounded transactions beneath original NFSD
controls, requires zero threads/empty ports/v3-only, absent fixed RPC listeners
and absent-before-start or empty-after-stop private export state. Original
namespace/source/code checks bracket the sample. This is not sole-domain,
complete cache or remote-client quiescence evidence. The Owner and original
backend causes remain retained after uncertainty; partial-start and live-fault
compensation are not made complete by this normal-path adapter.

`ProbeSourceLossFixtureQEMU` is a fault TEST, not a running/healthy state reply.
It requires the separate source-loss guest selector. Success means same-payload
directory substitution was detected with a real NFS file open, restoration could
not clear review, and ordinary client-unmount EBUSY kept original live consumers
and references. The join must remain reviewed; run/close refuse afterwards.
This does not authorize product activation, force unmount, certify remote-client
revocation/physical disk faults or turn VM disposal into verified settlement.

`WithdrawSourceLossFixtureQEMU` performs the fixed independent-budget shutdown
without clearing review or releasing parents/client references. A separate
`ProbeSourceDaemonLossFixtureQEMU` prepares the combined source fault, and
`InjectSourceMountdExitFixtureQEMU` admits one original-command termination only
with its additional explicit disposable-guest selector. It accepts no PID,
signal or replacement backend. The real exit must leave daemon review and
original kernel/rpcbind/client references; cleanup requires a distinct read-only
reviewed-stop witness before continuing. Generic Owner/Stop semantics do not
change. This is not independent daemon-only, hard-crash or product qualification.

## Tests and remaining integration

External-package units exercise actual lifecycle behavior with a memory model
and candidates built through the real planner. The shared `ExerciseQEMU`
campaign checks six memory-only lifetimes on both host and ARM guest. It never
starts a real server; its mandatory smoke receipt says `kernel_backend=false`.
Native race tests cover complete transition exclusion and retained review.

Next: a dedicated fixed kernel/userspace backend with retained namespace,
policy, source, runtime and control-domain authority, complete ownership census
and verified settlement. A successful callback in this trusted fixture seam is
not any of those proofs. Do not wrap the old path-based clean-reboot script as
a product constructor or infer complete kernel stop from zero threads.

Permanent export binding, qualified normal/unclean boot recovery, NLM/NSM,
protocol/client/ACL faults and hardware gates remain open. Automatic startup of
desired-enabled services after ordinary unclean shutdown remains required; the
single-use Owner is not an automatic restart loop or a boot coordinator.
See the [NFS runtime profile](../../../../support/NFS-RUNTIME-PROFILE.md).

## Independent mountd loss: verified reviewed compensation

The optional `source-owner-daemon-loss` fixture now passes in disposable ARMv5.
`Owner.InjectSourceMountdExitFixtureQEMU` holds the original Owner gate through
the fixed backend and lower original-child operation; it cannot bypass exclusive
supervision, operate through a copied Owner or use a model backend. No PID,
signal, command, descriptor or replacement backend is accepted from a caller.
The separate exact ARMv5/VersatilePB/source selector is mandatory.

After successful synthetic I/O, the fixture terminates mountd BEFORE admitting
supervision, so the mutation cannot contend with a scheduled check. Historical
Running does not certify daemon health; the subsequent scheduled scan must
detect the original exit. The reviewed access then admits one original-reference
compensation, using separate zero-capability/no-data-root server withdrawal
roles without relaxing the old source-loss selector. Original exports, NFSD and
peers are stopped; actual reviewed mountd Stop/cause stays retained.

Stop never becomes normal success. A separate fresh stopped observation checks
original controls, empty exports, fixed listeners and original process/group
absence before the join records the server absent. That diagnostic does not
require healthy service admission, clear review or authorize release. Policy/
identity claims remain valid; closure/retry/restart refuse and retained FDs stay
stable. All nine profiles pass, including a separate ordinary-wrapper execution.

The `source-owner-daemon-stop-loss` variant calls explicit Stop immediately
after the same exit, with no intervening Check or supervision. The same first
admitted Stop now retains its original precheck cause/phase and runs reviewed
compensation once after original-reference revalidation; review still returns.
Fresh stopped proof, retained claims/FDs and refusal after review are required.
The prior explicit-Stop checkpoint covers that variant twice and each earlier
profile once; the latest RPC-only partial-start campaign is described below.

The optional `source-owner-partial-start` variant now starts the real original
rpcbind and obtains readiness, then provokes an actual mountd constructor refusal
before acquisition. Compensation derives its frontier from original resources,
not the test flag, validates original references and stops only rpcbind once.
It cannot accept a non-nil failed mountd constructor result. Fresh original
stopped observations and actual RPC stopped-child proof qualify missing etab
only for this frontier. Review, original causes and authority remain held;
closure/retry/restart refuse with stable retained FDs. Nine fresh guests cover
this variant twice and each prior profile once, with27 receipt/shell groups.

The latest `source-owner-kernel-refusal` campaign prepares and retains an
independent original kernel controller before original rpcbind/mountd readiness.
Its real reservation refuses the server's second construction. The common
acquired-only cleanup stops both original daemons in reverse dependency order,
retains review/causes/claims/refs and invokes no kernel Stop/Close/replacement/
reset. Fresh original stopped observations and the original prepared controller's
read-only profile/reservation check remain mandatory. Nil is not never-acquired;
unknown/mixed frontiers and any attempted kernel Start refuse this partial path.
Ten fresh guests cover this case twice and eight prior profiles once, with29
receipt/shell and three loader groups at unchanged budgets. The reservation is
process-local, not sole OS-wide NFSD authority or product recovery.

The distinct `source-owner-kernel-bind-refusal` case exercises actual original
Kernel.Start bind-EADDRINUSE after both acquired daemons are ready. Original
policy/identity/storage/code/input refs remain mandatory. A read-only original
pending witness establishes the exact never-attached socket frontier; one
reviewed kernel Stop and separate fresh original stopped observation precede
mountd/rpcbind reverse stop. Fresh kernel/daemon/source observations are required
again before recording absence. The independent bound non-listening socket is
unchanged; exports were never activated. Original review/cause/claims/refs remain
held, with no retry/restart/release. This separate route does not capture normal
reviewed stopped servers or expand the constructor-conflict cleanup above.
Cached and ordinary wrappers plus ten previous profiles pass in twelve NFS
guests; API smoke and two clean state boots add three, not product qualification.

Other pre-dispatch/reference/admission failures, other partial-start/readiness/
uncertain-constructor/close outcomes,
hard crashes, complete faults, domain/client quiescence and product bootstrap/
recovery remain unqualified.
Generic process/Owner semantics and physical NAS operations remain unchanged.
