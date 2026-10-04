# Retained CHAP material — internal prerequisite

First-release storage policy permits **recoverable plaintext CHAP secrets** in
an exclusively provisioned root-owned directory (`0700`), with a root-owned
single-link regular document (`0600`). Encryption at rest is deferred; root or
offline-media access can disclose the credentials. This is not a production
credential service or authority to activate a target.

The Linux-only wrapper requires effective UID 0, trusted parent directories,
stable process credentials and a suitable local filesystem. It reuses
`revisionstore` for the retained directory lock, fixed-name no-follow reads,
bounded strict JSON, metadata/content checks, mutation watch and revision claims.
Opening retains the existing engine's reopen fsync boundary, not a promise of
zero filesystem effects. Missing/corrupt/pending/unsafe state is not initialized,
promoted or repaired. No public writer, generation, rotation, import, HTTP,
listener, startup or NAS operation exists. The QEMU-only provisioner writes
fixed **public synthetic tokens**, only to a newly created disposable directory.

The private document is versioned separately from desired NAS policy; policy
contains only `SecretRef`. The wrapper never exposes the disk document or a
generic snapshot/commit API. A claim resolves all policy references before
selecting a target. Missing refs, unsupported LIO `NULL`-prefix values/usernames
and duplicate bytes anywhere in the store refuse without partial material.
Printable 16–128-octet tokens are a bounded backend eligibility profile, **not
an entropy test**, protocol-wide password rule or security qualification.
Random generation/import provenance and client compatibility remain gates.
[RFC 7143 §9.2.1](https://www.rfc-editor.org/rfc/rfc7143.html#section-9.2.1)
requires strong randomly generated secrets and disjoint authentication roles;
CHAP by itself does not encrypt traffic and weak secrets permit dictionary attacks.

The trusted consumer is captured at claim acquisition; `Prepare` never accepts
a replacement backend and cannot be repeated after uncertain preparation.
Credentials/owners/claims reject JSON and redact all normal `fmt` formatting for
values and pointers. Opaque borrowed buffers expose only `WriteTo` to a trusted
credential sink, never a string/byte-return method. A sink still receives secret
bytes: it must obey `io.Writer`'s no-modification/no-retention contract and may
not log or make independent copies. These are trusted in-process boundaries,
not protection against malicious code/reflection/root.

The containing private lifecycle retains its **own** policy and credential
claims. Verified backend stop/join (including any kernel credential borrowers),
RW closure and metadata/mount reference closure must precede release. Drift or
uncertain preparation/stop permanently enters review; no implicit retry,
rotation, reset or restart occurs. Uncertain teardown retains buffers and claims.
Explicit release wipes owned buffers and invalidates all their borrowed handles;
it does not itself stop a consumer. Wiping is best effort for owned buffers only,
not guaranteed erasure of JSON, Go runtime, kernel, backend or crash-dump copies.

The current composition is a **single-backing lifetime prototype**, not a
target-wide/multi-LUN owner, qualified LIO adapter, entropy source, durable
rotation/recovery or product state placement. Product activation still needs
code/storage/access/allocation/global-use/session/network authority and actual
credential installation/readback/teardown qualification. Host synthetic sinks
and the mounted QEMU child do not prove iSCSI protocol authentication; the
separate [LIO research fixture](../../../../support/ISCSI-LIO-RESEARCH.md) covers
that different boundary.
