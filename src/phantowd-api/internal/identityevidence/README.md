<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors -->

# Stored identity-document comparison — M1.2c.7

Private portable DATA comparison for the proposed non-mutating startup path.
It does not construct IdentityOwner, open stores, read files, invoke Unix/Samba,
recover an interrupted operation or confer authority. Existing Owner startup and
its recovery behavior are unchanged. This is unrelated to the deferred Samba
status-producer experiment.

## Contract

`Match` receives the registry slot plus an explicitly complete, non-nil roster
of account-role names and native/optional enrollment journal slots. Names are
data, never paths. Slots distinguish present, absent and unavailable; failed
reads must never become absence. Inputs must remain immutable during the call.
The future collector must establish the actual census, original role/file locks,
mount/path/watch lifetime, pending-before-read refusal and provenance. This API
cannot establish those assertions, trusted installation identity or freshness.

Reuse `serviceaccounts.Decode`, `identityprovision.Decode` and
`smbprovision.Decode`; do not introduce a parallel JSON parser or state grammar.
Registry bytes retain their original256KiB limit, each journal4096bytes, at most
1024 named records, and aggregate4MiB including names and all supplied bytes.
The inclusive wire boundary is not a promise to accept every maximal combination
of individually allowed records. Unknown slot states, malformed present bytes,
bad sizes or unknown roster return only a zero result and fixed error.

All present documents are decoded before semantic diagnosis. Validate exact
role-name/account binding, duplicates/orphans, independent UID/GID/name links,
strict creation-revision ordering and registry bounds. At most one incomplete
native operation may belong to the current registry revision. An enrollment
journal requires the confirmed native revision; repeated nonempty SIDs refuse.
Known contradictions cannot hide behind unavailable documents. Retired ledger
records are explicitly unsupported in this startup prototype, never dropped,
reused, deleted or imported automatically.

Results distinguish no recorded registry, observed stored links, incomplete,
inconsistent, unresolved operation and unsupported registry state. Every result
permits **no action**. An absent registry is not pristine; observed links do not
prove native accounts, passdb, password readiness, sessions, successful historic
returns, whole-appliance coherence, migration or safe service activation.
Stable enrollment phases can still require explicit further work; this is not
an enrollment-completion or access decision. Identity entries and diagnoses
refuse generic JSON and redact normal formatting.

## Qualification scope

Host tests cover reordered rosters, immutable bytes, absent/unavailable/orphan/
duplicate/foreign roles, cross-document identities/revisions, duplicate SIDs,
uncertain phases, malformed-later precedence, retired records, empty registry,
exact max uint64 revision, individual/count/aggregate inclusive bounds, output
privacy and concurrent calls. The aggregate boundary uses deliberately repeated
names to test wire admission separately from a valid complete account generation.

The QEMU-tagged fixture compares eight public invented document sets in memory,
without filesystem/backend I/O or real accounts. It runs within the existing
standard API self-test, before/after API restart; strict receipt controls require
both exact rows plus all prior checks. No new guest or default build stage.
See [implementation status](../../../../IMPLEMENTATION-STATUS.md) for actual
terminal results; compilation alone does not qualify ARM execution.

An explicit experimental [retained namespace reader](../policyevidencefs/README.md#explicit-identity-namespace-profile--m12c8)
now supplies original locked files/censuses to this comparison without opening
the mutating Owner. Its separate qualification does not transfer authority to
this DATA API. Next: complete reader fault/resource qualification and composition
with the other original state roles. Product provisioning, live identity/passdb checks,
writer ownership/handoff, durable review/reconciliation, physical placement,
supported legacy migration and release qualification remain separate gates.
