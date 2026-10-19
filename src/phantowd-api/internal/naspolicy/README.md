<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors -->

# Coherent desired NAS service policy — M9.2c

This internal format puts SMB/volume/user, NFS and iSCSI desired policy in one
document. It is not a running-service snapshot, credential store or activation
capability. No backing/device/secret open, process, listener or HTTP exists here.

## Document and validation

Schema1 has exactly `format: "phantowd-nas-service-config"`, `schema_version`,
positive `revision`, `file_services` and `iscsi`. The nested documents retain
their existing strict formats and limits. All seven revision/binding values
must equal the outer revision: outer, file-service, SMB, NFS, NFS volume binding,
iSCSI and iSCSI volume binding. Even a one-protocol change advances the whole
document. Registry revisions and device generations remain separate authority.

Combined input is bounded to656128 bytes. The shared raw-envelope checker
refuses invalid UTF-8/surrogates, duplicate keys at any depth, nulls, trailing
data, excess depth and missing/unknown/miscased top-level fields. Child bytes
then go through their own strict decoders, including the required explicit
LUN number0 distinction. Child limits are not waived by the larger envelope.
Direct Go validation also checks component encoded limits. Every decode failure
returns zero state and one constant redacted error, never partial configuration.

SecretRefs remain symbolic IDs. Syntax does not resolve credentials or establish
entropy, naming ownership, volume qualification, permissions, allocation,
cross-protocol/global backing-use or session admission. A desired enabled target
does not authorize startup. Input slices remain caller-owned and must not be
mutated concurrently.

## Editing protocol views without a second configuration

`ReplaceFileServices` and `ReplaceISCSI` build a complete next-revision document
from a validated base and an explicitly base+1 protocol view. All seven counters
advance together; the other protocol's definitions and symbolic credential
references are preserved. Overflow, invalid/stale/skipped/mixed revisions and
invalid child limits return zero state and the constant `ErrInvalid`.

A file-service edit cannot remove or change a volume definition still referenced
by an iSCSI backing, even when its VolumeID remains the same. In particular,
changing the expected filesystem UUID must not silently redirect an existing
LUN. This is desired-model consistency, not physical volume qualification.
The returned document owns detached copies of all mutable slices, including
grants, NFS clients, LUNs and initiators. Caller inputs must not change concurrently.

These helpers perform no I/O or publication. A future writer must read and compare
the authoritative revision under the single state Owner and retain its recovery
contract; a detached candidate is not a revision claim or authorization. Do not
wire a second HTTP store around these helpers. No schema or startup change is
introduced, and saving a future desired edit will not itself activate services.

Native tests cover both views, cross-protocol preservation, nested detachment,
concurrent independent results, explicit empty collections, maximum revision and
19 invalid/stale/reference cases. A dense sample (128 users, 32 shares, 16 exports)
retains a 50,000-allocation regression ceiling per edit. Typed copying avoids two
complete JSON round trips while retaining base/candidate validation and encoded
child limits. This is not peak-RSS, every-policy-maximum or EX4 timing qualification.
The existing QEMU self-test checks seven synthetic cases on each side of its API
restart; its log verifier requires exactly two complete assertions.
That exact pair and the unchanged standard smoke checks pass in the actual
ARMv5 userspace overlay with pinned Go1.26.8. This uses a verified prebuilt
kernel/package base, not a clean image build, two-boot state campaign, EX4 test
or release qualification. No physical storage is involved.

## Store and migration boundary

The Linux [store adapter](../naspolicystore/store_linux.go) reuses the existing
revision engine: pre-provisioned private0700 local directory, lifetime exclusive
advisory lock, fixed descriptor-relative0600 files, expected-revision commit,
file sync, single rename and directory sync. Files are `nas-services.json` and
`.nas-services.pending`. Rename/sync uncertainty poisons the instance; pending
state is never automatically promoted and corruption is never empty state.

No existing `shares.json` or `file-services.json` is imported/renamed/deleted.
This is a distinct opt-in internal format; the old development HTTP adapter is
unchanged. Production must choose one protected state owner, not run independent
authoritative old/new writers. Explicit migration/recovery, product directory
placement and runtime composition remain work. An opt-in initialized-state
`OpenOwner` now retains the same engine and provides private all-protocol revision
claims: active leases block Commit/Close, while unexpected mutation or uncertain
publication enters permanent review. It does not migrate formats or prove live
consumer/session teardown. See the [owner contract](../revisionstore/README.md).
No device operation is authorized by this adapter.

The fixed NAS store codec additionally checks retained NFS export bindings before
publication, including the retained-policy Owner path. A source change under the
same export ID refuses without poisoning otherwise unchanged state. Standalone
desired previews/edit helpers are not historical validators or permission to
publish. Removed-ID reservation and the full release requirement remain in the
[NFS identity contract](../../nfsconfig/README.md#export-identity-continuity).

## Verification and remaining work

Windows strict-model/DOM/API checks and ARMv5 cross-compilation pass. Pinned
Go1.26.6 whole Linux QEMU-tagged vet/race, focused model/store/envelope race count3
and both two-protocol/three-protocol SIGKILL campaigns pass. Seven interruption
points run three repetitions with exact old/new whole-policy, pending evidence,
live child lock, confirmed SIGKILL and stale-writer checks. Hooks exist only in
test binaries; this is process-termination evidence, not physical power loss.

Actual ARMv5 Linux6.18.54 standard smoke and the generated-disk two-boot fixture
pass. Nonempty SMB/NFS/iSCSI policy survives clean restart; mixed/stale writes
refuse, valid pending/corrupt evidence stays preserved, and a subsequent explicit
commit reopens coherently. No real backing file or credential is opened, no
target/service starts, and no old file format is created by the new store.

This is a cached userspace overlay, not clean-build or EX4 qualification. Next
compose the retained policy owner with qualified registry/mount/identity and
global-use/session/credential admission before any controlled RW opener or
target backend. Durable live mutation, activation UI and migration stay separate.
