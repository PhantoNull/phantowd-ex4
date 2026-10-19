<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors -->

# Experimental NFS lifetime owner

This package exists only with the `qemu` build tag. It implements the approved
host/disposable-QEMU lifecycle, **not a kernel backend or product NFS manager**.
Normal firmware builds cannot construct it. There is no HTTP endpoint, command
execution, namespace setup or physical-device operation here. The Linux/QEMU
source lifetime below opens directories only through an original mount lease.

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
