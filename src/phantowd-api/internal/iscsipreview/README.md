<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors -->

# Desired iSCSI review projection — M9.2f

`Build` accepts the existing coherent `naspolicy.Config`, validates the entire
SMB/NFS/iSCSI revision and returns a caller-owned display projection. It does
not parse an independent policy dialect, select/migrate a store, open a backing
or credential, inspect storage/network/session state, save or activate anything.
There is no HTTP route, product startup or UI in this increment.

## Display contract

Schema1 `phantowd-desired-iscsi-preview` uses `scope: desired-policy-only` and
explicit false storage/credential/runtime validation and activation flags.
Target state is `desired_state`: enabled never means running. Show complete
target/LUN/initiator/grant relationships, proposed backing allocation/block size,
volume-relative path and logical VolumeID. Counts of the coherent SMB/NFS
definitions are context, not overlap/global-use or effective-access checks.

Revision and capacity bytes are **decimal strings**, preserving exact uint64
values in JavaScript. Counts, block sizes and LUN numbers are bounded integers.
The explicit empty policy yields empty arrays, not missing evidence. Preserve
input order and never truncate an accepted roster; encoded output is capped at
256 KiB. Invalid/incoherent/oversized output returns a zero value and constant
redacted error. Inputs must not be mutated concurrently; returned rows/grants
do not alias input or later output. No retained owner claim is established.

Credential usernames, SecretRefs and raw filesystem UUIDs are omitted. Proposed
IQNs and paths are still sensitive administrative data: this is **not** a public
support-report sanitizer. Any future HTTP adapter needs authenticated/origin/
body/response bounds; the browser must use text rendering and preserve desired,
unverified and unavailable distinctions. CHAP does not encrypt data traffic.

## Verification and next boundary

Host controls cover whole-revision refusal, invalid references/RO escalation,
zero versus explicit empty, metadata redaction, defensive copies, exact maximum
revision/aligned capacity and a dense 64-backing/4-target/64-initiator/1,024-grant
fixture. A bounded arbitrary-JSON campaign reuses the existing strict coherent
decoder before projecting, with no partial failure or runtime authority.
The existing pure same-boot QEMU iSCSI fixture additionally checks projection,
SecretRef omission, exact values and stale-policy refusal. It performs no new
I/O and adds no guest boot. Actual qualification scope is recorded in the
repository implementation status; compilation alone is not guest execution.

Next is a separately scoped authenticated manual preview/panel, not a second
authoritative writer. The interface preference is pending; no response is not
approval. Durable state migration, provisioning/recovery, storage/global-use,
credential/session/network authority and target activation remain separate.
