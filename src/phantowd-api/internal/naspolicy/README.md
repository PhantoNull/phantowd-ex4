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
placement and retained policy/runtime ownership remain work. No device operation
is authorized by this adapter.

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
compose a protected policy owner with qualified registry/mount/identity and
global-use/session/credential admission before any controlled RW opener or
target backend. Durable live mutation, activation UI and migration stay separate.
