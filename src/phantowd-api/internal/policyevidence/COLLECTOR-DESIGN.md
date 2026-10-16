<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors -->

# Retained policy-operation observation — M1.3b.3 proposal

**Status: product contract remains proposed; an experimental internal
[read-only prototype](../policyevidencefs/README.md) now exercises this boundary
on host/QEMU, not product namespace/writer/recovery/boot/NAS approval.** The
private record codecs/matcher are already implemented and separately approved.
This document describes their filesystem boundary, not a second policy store.
The prototype requires unique mount IDs and rechecks the original root path;
its README distinguishes actual ARM evidence, native skips and remaining gates.

## Authority that must actually be retained

The existing revision Store exclusively locks its **policy directory**. A lock
on a common ancestor or sibling is not a substitute. The Linux adapter regression
`TestBootstrapParentAndSiblingLocksDoNotReplaceOriginalPolicyLock` exercises the
actual Store and retained bootstrap observer on temporary files: with ancestor
and sibling locks held, Store still enters; while the original policy observer
is retained, Store refuses with Busy; releasing it admits Store again even
though the other locks remain. An independent test-binary process verifies
allowed/Busy/allowed under the same retained ancestor/sibling locks, without
inheriting their CLOEXEC descriptors. This is not a collector implementation.
Each child must exit successfully and emit one exact, unique mode-bound receipt;
an empty, duplicate, lookalike or `no tests to run` output is not verification.

Consequently, keep the actual policy-directory lock continuously. Do not close
the bootstrap observer and reopen an Owner, rely only on a new root lock, or
invent an independent writer whose lock the old Store never takes.

## Proposed fixed layout for host/QEMU composition

Use one independently provisioned private state root with fixed `policy/` and
`operations/` directories. The policy child retains existing `nas-services.json`
and `.nas-services.pending` semantics; do not add record files there. The separate
operations child has fixed `intent.json` and `receipt.json` roles using the
approved private record codecs. This is an experimental diagnostic layout, not
a physical EX4 path or a complete writer/boot bundle. A future writer also needs
preserved base/staging/retention roles and a separately reviewed namespace/version
and atomic-publication strategy; do not silently extend this census.

A constructor captures the root and expected installation ID once. Proposed
dedicated Linux package: `internal/policyevidencefs`, keeping OS access out of
the pure codec package. No request supplies a path, role name, UID, codec or
replacement backend. No generic descriptor or raw policy is returned to HTTP.
The expected ID is a trusted caller assertion, not installation provenance.
Holding a directory descriptor does not prove that its original pathname still
resolves to that mount. In particular, a bind mount over a retained root may hide
it without changing the held inode/device. Root-origin and mount-substitution
checks need qualification before implementation can claim current-path authority;
do not silently weaken them when a host kernel lacks the required observation.

## Proposed open/read/close lifetime

1. Require context, an absolute clean trusted root, owned0700 directories and
   separately established trusted parents/local-filesystem prerequisites.
   Open read-only/no-atime/no-follow/CLOEXEC; no mkdir, fsync or fallback.
2. Retain original root then policy then operations descriptors and exclusive
   non-blocking directory locks in that fixed order. Open descendants relative
   to the root with no symlink/magic-link/cross-mount traversal. Require distinct
   directories and the same root medium; device-number equality alone does not
   allow nested bind mounts. Other role owners/writers must honor these locks.
3. Retain mutation watches for all three directories and original identity,
   ownership/mode/content metadata. Require real procfs if using its descriptor
   paths to install watches. No silent degraded mode when a check is unavailable.
4. Completely census the bounded fixed role set before content reads. Unknown,
   duplicate, unsafe or over-budget entries produce no match. Files must be
   owned0600 single-link regular objects on the retained medium. Use nonblocking
   opens to avoid a FIFO replacement blocking before type checks. A failed read
   never becomes Absent. Missing current policy is incomplete, not pristine.
5. Keep original file references through observations where present; recheck the
   named entry against the held object and all original roots before/after reads.
   Use bounded read-at offsets, not a borrowed mutable file cursor. Check context
   between chunks; byte limits do not promise interruption of kernel storage I/O.
   The staged policy role is metadata-only: its presence requires review and
   must not be parsed, adopted, deleted or mistaken for a confirmed publication.
6. Serialize observations on the same lifetime. Build complete private slots,
   invoke the existing pure matcher, clear owned temporary buffers and publish
   only its redacted diagnosis after final metadata/watch/context fences. No
   raw record/policy/ID/digest/descriptor or lease is returned. A valid but
   inconsistent/unconfirmed document remains diagnostic, never an action token.
7. Drift, watcher loss/overflow, admitted cancellation, uncertain read or closure
   permanently latch instance review: no refresh/reopen/retry after restoration.
   Return standard `ctx.Err()` classification, not private `context.Cause` text.
   Cancellation before admission does not modify authority. Copied/zero handles
   and generic JSON/ordinary formatting cannot transfer or disclose authority.
8. Explicit Close serves no consumers and releases only this observer. Verify
   each close in a fixed order; the first uncertainty is terminal, retaining
   unattempted originals/metadata without retrying a raw descriptor. Do not claim
   a failed close necessarily kept its kernel lock. Instance review is not a
   durable quarantine or protection against root/rollback/cloned state.

## Acceptance before any product wiring

- Actual old Store exclusion under the **same** policy lock, retained across
  repeated reads; independent root/sibling locks never stand in for it. The
  adapter-level subprocess case does not qualify the future whole collector.
- Nonempty three-protocol current/intent/receipt fixture; all six matcher kinds
  retain their no-action meanings. Verify byte-for-byte unchanged files, atime
  policy, no new entries and bounded descriptor use over repeated observations.
- Complete census refusals: extra/duplicate entries, missing required directories,
  wrong modes/owners, links, symlinks, FIFO/socket/directory masquerades, zero or
  oversized present files, pending evidence and cross-mount/bind substitutions.
- In-place edit, replacement, directory substitution and unchanged-data writable
  open/close all preserve sticky review after restoration; no stale positive.
- Pre-admission versus in-flight cancellation, watcher loss/overflow, short/read
  failure, cleanup failure and uncertain close return no diagnosis or fallback.
  Controlled hooks/fd faults are labelled, not claimed as real media EIO.
- Zero/copied/serialized handles, concurrent Observe/Close, private formatting,
  standard-context errors, actual child-lock release and original-state retention.
- Fast host checks, pinned Linux units/vet/race, then bounded disposable ARMv5
  tests. Reuse an existing guest or optional fixture; do not add historical image
  stages, persistent Docker images/volumes, product startup or physical devices.

The collector still cannot prove historical fsync returns, browser delivery,
first-owner provisioning, safe media, global consumer absence or complete boot
state. Review [recovery requirements](../revisionstore/RECOVERY-DESIGN.md) before
designing the one-attempt writer, explicit reconciliation or admission.
