<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors -->

# Desired revision store and retained policy claims

The Linux transaction engine uses one pre-provisioned, owned0700 local
directory, a lifetime exclusive advisory flock, fixed0600 files, bounded strict
trusted codecs, file sync, one rename and directory sync. It never imports old
formats, promotes pending state or treats corruption as empty configuration.
`Store` remains the original snapshot/transaction API.

## Read-only policy-directory bootstrap observation

`OpenBootstrapAuthorityWithCodec` optionally retains one directory/flock/
trusted-codec/watch lifetime. Fixed `naspolicystore.OpenBootstrapAuthority`
chooses NAS roles. Observe is serialized and uses fresh confined cursors on
the original directory plus the same collector below; it does not reacquire
a path or accept a per-call backend. Other writers are excluded between reads.
Drift/read uncertainty, including unchanged-data writable open/close and
in-flight cancellation, latches review. Prework cancel has no effects; restored
inputs cannot resume. Copies/serialization cannot transfer read/disposal rights.

No leases/consumers are issued. Explicit Close disposes only this observer;
uncertain close is terminal, preserving unattempted roots without retry. The
premature-watch-descriptor test characterizes this refusal, not actual media
EIO. Review remains instance-local, not a durable recovery record. No init/
write/admission/Owner handoff/journal/HTTP/startup is implemented. A future
receipt/state-bundle contract must govern boot and operator recovery.

[Recovery design and work packets](RECOVERY-DESIGN.md) propose versioned private
intent/receipt matching before any writer or admission change. It is not yet an
approved schema or implemented recovery mechanism. Local recorded confirmation
and response delivery are distinct; restoring valid bytes does not settle an
interrupted operation or clear prior review.

Whole tagged pinned API vet/unit/store race3, Windows and actual ARM52 ordered
receipts pass with strict2+133, normal unmount/base hash and unchanged limits.
No new default boot/Docker storage/NAS/privilege or removed older assertion.
The standalone observer remains its separate temporary-lifetime interface.

`ObserveBootstrapWithCodec` returns only kind/revision; the fixed
`naspolicystore.ObserveBootstrap` adapter selects NAS names/schema. Codec code
is trusted in-process, not HTTP-supplied. No syncing constructor, initialization,
import/promotion/deletion, claims or changed Store/Owner admission is invoked.
The temporary exclusive flock requires trusted parents/cooperating writers,
an owned0700 directory and safe owned0600 single-link regular named entries.

Kinds: `empty-directory`, `valid-current-policy`, `pending-evidence`,
`invalid-or-unsupported-policy`, `unrecognized-entries`. Only valid current
data yields a positive revision. Pending is metadata-only and takes precedence;
unknown evidence is preserved and never a usable-directory claim. Errors yield
zero, not empty state. Empty directory is not whole-NAS pristine; valid current
bytes do not prove origin, acknowledged commit or filesystem durability.

Census stops at three names; empty/known-only outcomes require EOF. Current
reads reuse no-follow/no-cross-mount/O_NOATIME and trusted codec limits, checking
context between at-most64KiB reads. Metadata brackets and a nonblocking empty
inotify epoch refuse drift, including write-capable open/close with unchanged
data/metadata. I/O is not guaranteed immediately cancellable. This is point-in-
time on the held directory, not continuous/parent-path/retained admission.
Invalid versus incompatible versions, whole state bundle/provisioning, durable
review and operator recovery remain separate; no auto-reopen can erase review.

The optional ARM ext4 lane now requires47 ordered PASS receipts including ten
bootstrap groups, fixed adapter and every prior interruption/media assertion.
Whole tagged pinned host vet/units/scoped race3 and Windows pass. A two-driver
aggregate raw capture was truncated; a same-source guest supplies all47 complete
receipts independently matched. Strict2+123/no-skip/unmount/base-hash checks
pass with no default CI/storage/timer/privilege/NAS change. No installable
product or durable recovery is qualified by these observations.

## Optional initialized-state owner

`OpenOwnedWithCodec` privately retains that engine and requires initialized
valid state. `naspolicystore.OpenOwner` fixes the three-protocol codec/names;
no operation accepts a new backend, path, decoder or filename. `OwnedStore`
provides fresh defensive `Snapshot` values and bounded opaque `PolicyLease`
claims on an exact positive revision. Up to256 claims are held in memory;
ordinary observations open/close one file and do not accumulate descriptors.

Active claims fence both Commit and Close, including after review. Release
removes only the explicit policy claim: the caller must first independently
confirm consumer teardown. The owner does not start/stop processes, track
sessions or prove their exit. A future service owner must retain this private
claim through live/uncertain consumers; handing it to an HTTP caller is invalid.

Lock order is owner then underlying store. A self-identity guard rejects zero,
forged and copied owners/leases; pointer JSON serialization/deserialization is
refused. Released claims cannot observe or regain authority. Snapshots/counters
are never capabilities and never bind volumes, identities or credentials.

## Mutation and publication semantics

Owned reads use O_NOATIME and Openat2's beneath/no-cross-mount/no-symlink/no-magic-
link resolution on the fixed current filename. Before/after file and directory
metadata brackets include identity, links, mode, owner/group, size, mtime/ctime
and a digest of the strict decoded document, but ignore access time. A private
nonblocking inotify epoch requires an empty mutation queue before/after reads.
Any event, overflow, watch loss, read/close error or unexpected stamp/content
change enters permanent review; restoring bytes/inodes does not revive it.
There is no background thread, autonomous supervisor, retry or event-name parser.
Even unrelated changes in this exclusively owned directory are conservative
review. The retained directory descriptor is the anchor; this is not a supervisor
of arbitrary replacements/overmounts of its external parent pathname.

With no claims, a valid explicit Commit reuses the original transaction. It
establishes a fresh watch epoch and verifies the exact published revision and
document. Invalid/stale input has no publication effects; any attempted I/O or
uncertain publication fails to review, preserving current/pending evidence.
Cancellation before work has no effect; cancellation after publication is
review, never a claim that nothing changed. A failed Close is not retried using
possibly reused descriptor numbers. Close cannot drop a lock under live claims.
Context is checked before/after serialized work; regular-file I/O is not
guaranteed nonblocking or immediately cancellable.

All writers must cooperate with the flock and the directory must have trusted
parents/provisioning on a qualified local filesystem. A same-UID/root adversary
can violate these prerequisites; advisory locking/inotify are not a sandbox.
Successful observations are point-in-time, not continuous protection or an
authenticated runtime manifest. Review is sticky for the instance lifetime,
not a durable recovery journal. A fresh owner is not an operator recovery plan
and must not be automatically opened to bypass an earlier uncertain outcome.

## Verification boundary

The original media-only `support/test-revisionstore-media.ps1` checkpoint ran seven
SIGKILL boundaries for both nonempty SMB/NFS and three-protocol NAS policies on
synthetic ARMv5 ext4. A32-MiB snapshot also exercises actual full/read-only media
against initialized `OwnedStore`: failed Commit, retained lock/sticky review,
refusal after restoration, unchanged confirmed policy and pending preservation
on explicit fixture reconciliation without consumers. No store/Owner production
behavior is replaced; no fake syscall failure is injected in the media cases.
All18 ordered test receipts had to PASS, not skip; two consecutive guests, pinned
host vet/unit/race3 and strict2+64 log controls pass with normal unmount/base
hash unchanged. Outside the exact marked ARM guest, the media tests do not run.

A growing file's ENOSPC did not exhaust every usable block. The harness now
uses a bounded fresh-file tail fill and still requires zero available blocks
before publication. This fixes test setup, not a demonstrated production defect.
The kernel remains alive during SIGKILL; this is not sudden-power-loss/cache-
flush qualification. Review remains instance-sticky, not a durable journal.
No product recovery/reopen, selected-medium durability, EX4 state placement or
hardware/installer/full/hosted qualification follows from these fixtures.

Native tests cover claim fencing, defensive values, bounds/concurrency/FD use,
restored mutations, mutation during decode, uncertain writes/sync/rename/close,
post-publication cancellation and retained locks. The existing generated-media
ARMv5 two-boot fixture checks nonempty SMB/NFS/iSCSI claims, publication/close
fences, a subsequent coherent epoch and permanent review after in-place byte
restoration. This adds no boot, real backing/credential open or service launch.

Product boot/state placement, legacy-format migration, runtime/identity/registry/
mount/access/allocation/global-use/session/credential admission, autonomous
supervision, power-loss recovery and EX4 qualification remain separate work.

Windows preflight/cross-compilation, pinned Go1.26.6 whole Linux tagged vet/race
and focused race count3 pass locally. Actual ARMv5 Linux6.18.54 standard smoke
and the complete two-boot state fixture pass with the new mandatory owner
marker and all old assertions retained. This uses a bounded discarded overlay
and existing manifest-verified base, not a clean Buildroot/hosted result.
