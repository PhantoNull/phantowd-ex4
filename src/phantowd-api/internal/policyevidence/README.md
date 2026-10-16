<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors -->

# Private policy operation evidence — M1.3b.1/b.2

Strict in-memory codecs and a read-only diagnostic matcher for coherent desired
SMB/NFS/iSCSI policy. This is **not** a journal writer, retained filesystem
collector, recovery engine, boot permission or HTTP API. Existing Store/Owner/
BootstrapAuthority behavior is unchanged. The approved first slice implements
the [operation-evidence design](../revisionstore/RECOVERY-DESIGN.md); later writer,
namespace/publication, retention, reconciliation and provisioning decisions remain.

## Private record schema

Both flat schema1 records have `format`, `schema_version`, `installation_id`,
`operation_id`, `base_revision`, `next_revision`, `base_sha256`, `next_sha256`.
Format is `phantowd-nas-policy-intent` or `phantowd-nas-policy-receipt`; the
receipt additionally requires exactly `phase: "local-confirmed"`.

IDs are nonzero32-character lowercase hexadecimal values, separately supplied
by a future trusted coordinator, not derived from a bay/path/device identifier.
Positive uint64 base/next revisions are consecutive without overflow. Digests
are64-character lowercase SHA-256 strings binding **exact policy bytes**, not a
JSON re-encoding or semantic equivalence. A record asserts these bindings; it
does not itself prove the reads, identifier provenance or synchronization.

Decoders accept bounded readers (at most4096bytes per record, depth2), reusing
the existing envelope's exact-key/duplicate/null/Unicode/trailing checks. Fields
cannot contain secrets, arbitrary paths, timestamps or response acknowledgements.
Unknown phases/versions, malformed values, read failures and oversized inputs
return zero values and a fixed error. Byte bounds are not an I/O deadline on a
caller-supplied reader. Explicit Encode/Decode functions handle private records;
normal JSON serialization/deserialization is refused and normal `fmt` output
is redacted for records, evidence slots, input and diagnosis. This is not a
defence against reflection, malicious in-process code or root.

## Matcher contract

The trusted caller supplies the expected installation ID and three explicit
slots: intent, receipt and current policy. Each is Present, Absent or Unavailable
(the zero state). Absent/Unavailable cannot carry bytes; Present requires bytes.
Failed reads must never become Absent. Missing/unavailable roles yield incomplete
evidence without parsing partial contents. Unknown state values and present
empty slots fail; malformed contents fail when all roles are known. Callers
retain their slices and must not mutate them
concurrently; no references to them are retained after the call.

When complete, Match decodes both records and validates the current **whole
coherent NAS policy**, all component schemas/revisions and its existing656128-
byte ceiling. It compares the tuple and the current revision plus exact SHA-256.
Only the observed current policy is validated: a non-current digest remains a
record assertion, not proof of valid historical base/candidate bytes.

| Complete observations | Redacted kind |
| --- | --- |
| Valid policy, both records absent | `no-recorded-operation` — not pristine or boot-authorized |
| Intent only, exact base current | `intent-base-observed` — no replay permission |
| Intent only, exact next current | `publication-unconfirmed` |
| Matching intent/receipt, exact next current | `local-confirmation-observed` — matching records, not proof of historical syscall returns or browser receipt |
| Orphan/mismatched/foreign records, unrelated policy, receipt with base current | `inconsistent-evidence` |
| Any unavailable role or missing current policy | `incomplete-evidence` |

**Every result authorizes no action.** Hashes are not authentication; caller
assertions are not retained-origin evidence. Restoring an old complete bundle
or cloning installation IDs is not detected by this slice. It opens/syncs/
writes/renames/deletes nothing, generates no IDs or receipt, issues no lease,
and never initializes, recovers, retries or activates anything.

## Verification and next step

Unit controls use a nonempty three-protocol before/after pair, all kinds and
tuple bindings, malformed records/policies, orphan/foreign/incomplete evidence,
exact-byte versus semantic changes, maximum uint64 revisions, inclusive byte
limits, privacy and zero-on-error. Two bounded fuzz targets exercise codecs and
matching; the matching campaign caps current-policy mutation input at8192bytes,
while explicit units cover the full656128-byte bound. Local execution evidence
is recorded in [implementation status](../../../../IMPLEMENTATION-STATUS.md).

A pure QEMU-tagged fixture reuses synthetic policy definitions, checks all six
kinds, exact-byte refusal and private codec/diagnostic boundaries in the existing
standard smoke. It adds no filesystem operation or guest boot. Compilation is
not execution; ARM evidence is separate from physical EX4/media qualification.

Next is a separately scoped retained read-only collector over a defined complete
role namespace, with no-follow/same-medium/permissions/identity/lifetime and
drift/cancellation/close-fault checks. Do not add record files to the existing
two-name policy directory: its census intentionally rejects unknown entries.
Writer/provisioning/reconciliation and state-root atomicity remain later gates.
The [proposed collector contract](COLLECTOR-DESIGN.md) records exact lock,
namespace/lifetime and refusal requirements; it is not an implemented collector.
