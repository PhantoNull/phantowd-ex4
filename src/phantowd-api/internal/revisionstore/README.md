<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors -->

# Desired revision store and retained policy claims

The Linux transaction engine uses one pre-provisioned, owned0700 local
directory, a lifetime exclusive advisory flock, fixed0600 files, bounded strict
trusted codecs, file sync, one rename and directory sync. It never imports old
formats, promotes pending state or treats corruption as empty configuration.
`Store` remains the original snapshot/transaction API.

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
