<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors -->

# Desired iSCSI review projection — M9.2f

`Build` accepts the existing coherent `naspolicy.Config`, validates the entire
SMB/NFS/iSCSI revision and returns a caller-owned display projection. It does
not parse an independent policy dialect, select/migrate a store, open a backing
or credential, inspect storage/network/session state, save or activate anything.
`Build` itself has no HTTP or startup authority. The separate M9.2g adapter
now exposes a manual authenticated preview; it does not persist this projection.

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
support-report sanitizer. The HTTP adapter requires session/Origin/CSRF and
bounded input/output; the browser uses text rendering and preserves desired,
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

## Manual HTTP/UI adapter — M9.2g

`POST /api/v1/iscsi/preview` receives one complete coherent NAS document, not
the older SMB/NFS backup. It requires a current panel session, exact Origin,
one valid CSRF header and JSON without query or content encoding. Input is
bounded at656128 bytes including streamed bodies; exact JSON output is at most
262144 bytes. A dedicated non-queuing gate admits one preview. Authentication
is checked before reading and again before publishing. Refusals are fixed and
redacted; the handler has no store, backing opener, secret resolver or backend.

The dashboard submits only on explicit review, with one ten-second deadline
across session lookup, POST headers and bounded response bodies. Editing,
clearing or session retirement invalidates pending work and old results; late
completions cannot retire a replacement view. Session loss also clears source
text. No browser storage, automatic retry, save or activation request is used.
Visible clearing is not a claim of browser-memory zeroization. Never paste
actual passwords or keys: this document uses symbolic credential references.

Host/DOM controls exercise authorization, strict envelopes, revision refusal,
inclusive bounds, gate release, revocation, exact decimals, display validation,
four stalled-request seams and replacement-view retirement. A disposable real
browser tests text/pointer submission against the actual memory-auth Go fixture,
clear and narrow layouts. The standard ARMv5 smoke exercises the actual HTTP
and HTTPS routes twice each across API restart, without opening backings or
credentials. QEMU does not execute the JavaScript or qualify EX4 hardware.

Durable state migration, provisioning/recovery, storage/global-use, credentials,
sessions/network authority and guarded target activation remain separate.
