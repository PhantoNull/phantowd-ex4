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
mounted-roster sources and runtime references. It does not expose a backend
factory, replacement inputs, HTTP or a product constructor. Both containing
join/root gates remain held throughout this finite campaign; runtime gates
still return before callbacks enter storage/identity domains.

Start and explicit Check use the actual server. Accepted supervisor cancellation
while idle stops it independently of that canceled request; explicit Close then
releases only owned source duplicates, not borrowed authorities. The campaign
witnesses exclusive loop admission before cancellation with a fixed one-hour
idle interval. It therefore proves idle cancellation, NOT periodic real-server
scans. Generic model tests separately cover periodic scans and drift.

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
