<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors -->

# Desired iSCSI policy — M9.2a task contract

This internal, backend-independent package models desired targets, file-backed
LUNs and per-initiator access. It does not open backing objects, resolve secrets,
allocate files, configure configfs, listen, invoke a target or persist anything.
Its positive revisions are not transactions or permission to activate a LUN.

The separate Linux [registered-volume review](../../README.md#m92b-registered-volume-and-cross-protocol-review)
compares this model with protected registry/census observations and SMB/NFS
path advisories. That comparison is not part of this parser's authority: it
opens no backing/secret and provides no lease, admission token or activation.

## Inputs and ownership

Schema 1 binds to the exact revision of a validated `shareconfig.Config` and
references its logical VolumeIDs, never bays, `/dev` names or filesystem UUIDs.
Targets, LUNs and backing objects have independently assigned stable logical IDs.
The backing object has a volume-relative file path, explicit byte capacity,
512/4096-byte logical block size and desired `preallocated`/`sparse` allocation.
No default allocation, access or target state is inferred. These desired modes
are not qualified backend capabilities or proof of size, reservation or space.

Each backing belongs to exactly one LUN; IDs and same-volume equal/ancestor file
paths cannot alias other backing definitions. Each target has unique LUN numbers
and an explicit nonempty initiator roster. Per-initiator grants reference stable
LUN IDs, not array positions. Read-only LUNs cannot grant read-write access.
Unused backing definitions and grants to another target's LUN are refused.
No shared-disk multi-initiator filesystem safety, global-use ownership, hardlink/
symlink containment, actual file identity or SMB/NFS overlap proof is implied.

The initial naming profile accepts canonical lowercase ASCII IQNs of at most
223 bytes, Gregorian `yyyy-mm`, reverse-DNS labels and optional bounded suffix
using letters, digits, dot, hyphen and colon. It never normalizes names or invents
a naming authority from a hostname/domain. This is an explicit interoperability
subset of [RFC 7143 sections 4.2.7 and 9.2.1](https://www.rfc-editor.org/rfc/rfc7143.html),
not proof of authority ownership or worldwide uniqueness. Unicode/stringprep,
EUI/NAA names and legacy name import need a separately qualified extension.

## Credentials and failure

The initial model requires explicit `chap` or `mutual-chap` for each initiator;
no-auth and wildcard access are unsupported. Credential usernames are bounded
ASCII identifiers, separate from initiator IQNs. Only opaque SecretRef IDs occur
in the model. Mutual CHAP requires distinct inbound/outbound references; no
reference is reused anywhere in the policy. Secret presence, different secret
bytes, entropy, storage/rotation and backend authentication still require a
trusted credential owner. CHAP does not imply traffic encryption.
This is a conservative development profile, not a finalized legacy-migration
or product authentication policy. A pending operator preference can extend the
model; it cannot silently authorize a live unauthenticated target.

All collections, strings, nesting and serialized input are bounded. Empty policy
is valid only with explicit empty backing/target arrays. Missing fields fail;
in particular the JSON LUN number is required even though zero is valid. Decode
returns a zero policy and one constant redacted error on every failure, including
I/O, invalid encoding, duplicates, unknown/miscased fields, nulls, stale volume
revision, wrong shapes and relationships. Validate covers direct Go values.
Neither operation changes inputs or owns a resource; no retry/fallback exists.
The limits are 128 KiB JSON, 16 targets, 64 backing objects, 16 LUNs and 32
initiators per target, 64-byte logical IDs, 1024-byte file paths and 128-byte
credential usernames. Capacities are positive, block-aligned and at most
`MaxInt64`; exact Go integers are not a promise of browser-number precision.
LUN numbers are uint16 syntax, not a qualified backend LUN-addressing range.

## Acceptance and next boundaries

Host tests cover positive mixed access/allocation, zero/nonzero LUN numbers,
stable references, credential separation, bounds/overflow, path aliases, strict
JSON including absent zero-valued fields, and redacted all-or-error behavior.
Use fixed-count malformed-input testing and a pure same-boot ARMv5 self-test,
without extra disks or a target process. Full QEMU integration remains separate.

Before activation: select/qualify M9.1 backend and supported names/backing modes;
add protected credential/state ownership, full storage/global-use admission,
network binding, real initiator/session observations and M9.3/M9.4 guarded
transactions/import/failure campaigns. No HTTP, product startup, new privileges,
NAS/HDD/NAND/flash operation or release/migration qualification is introduced.
