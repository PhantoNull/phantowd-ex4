# Atomic desired file-service configuration (Linux)

This library saves SMB share/volume/user policy and NFS export policy as one
versioned document. It is a prerequisite for management saves, **not** an HTTP
save endpoint, product state provisioner or service activator.

## Document

The top level has exactly `format: "phantowd-file-service-config"`,
`schema_version: 1`, positive `revision`, `shares` and `nfs`. The latter two
retain their existing strict schemas and per-document 256 KiB limits. The
combined input is limited to 524,800 bytes. Duplicate/unknown/missing/null
fields, malformed Unicode, unsupported renderings and trailing data are refused.

All four revision values must match: top-level revision, share revision,
NFS revision and NFS volume revision. Even a change only to NFS creates a new
whole-document revision. This intentionally trades independent component
counters for an unambiguous optimistic-concurrency boundary. NFS permissions
remain independent of SMB grants; coherently saved policy is not proof of
cross-protocol effective access or volume safety.

## Storage

`Open` uses the same internal revision engine as the original share-only
store: existing private 0700 local directory, lifetime exclusive lock,
descriptor-relative files, validated `Commit(expected, next)`, file sync,
one rename and directory sync. The files are `file-services.json` and
`.file-services.pending`, mode 0600. No half-SMB/half-NFS transaction exists.
The [share-store contract](../sharestore/README.md) also applies: corruption
is not empty state, pending files are never promoted, and rename/sync
uncertainty poisons the instance until close/reopen and reconciliation.

The directory is separately provisioned by a future state owner. The original
`shares.json` adapter, filename and API remain unchanged. No existing state is
automatically imported, renamed, deleted, or treated as an initialized combined
store. Do not configure both formats as independent authoritative writers;
explicit migration and a single management-state owner remain work.

## Validation boundaries

### M1.4 abrupt-writer interruption contract

The Linux revision engine's test-only campaign must kill a separate writer
with SIGKILL after partial/full pending writes, successful file sync/close,
before/after publication, and after successful directory sync. The parent
must first observe that the live child retains the exclusive store lock.
After confirmed signal termination, reopening must return exactly the old or
new **whole nonempty SMB/NFS policy**, according to the reached boundary,
never a mix, empty fallback or promoted pending document. Load/reopen must
preserve abandoned pending bytes; only a later explicit revision-checked
commit may discard the reserved regular pending entry. A stale revision must
still be refused, and a subsequent explicit commit must succeed coherently.

Use the existing private syscall seams in tests only; production code gains
no interruption hook. Bound child lifetime and wait for cleanup on every
exit path. All files are temporary regular files, no mounted device or NAS.
This is native process-termination evidence with a live host filesystem,
not QEMU/EX4 execution, power-loss durability or product recovery approval.

Local evidence (2026-10-03): all seven boundaries pass three consecutive
Linux amd64 race-enabled repetitions using Go 1.26.6, followed by complete
API `-tags=qemu` vet/race tests. The pinned container is non-root,
zero-capability, network-disabled, read-only, with disposable tmpfs fixtures.
Windows API/UI/vet checks and ARMv5 cross-compilation also pass, but do not
execute this Linux campaign. No product code or firmware input changes.

Host tests exercise strict decoding, mismatched revisions, complete reopen,
stale writers, snapshot independence, locking, corruption preservation, and
injected write/sync/close/rename errors in the shared engine. A rename that
publishes before reporting an error is also tested. These are simulated syscall
failures, not power-loss tests. The QEMU two-boot fixture additionally checks
nonempty SMB/NFS policy and grants across two clean virtual-kernel boots,
pending refusal, corrupt-state preservation and another commit after restart.

No hardware disk, NAND, account provisioning or running service is controlled
by this library. Filesystem-qualified interruption tests, recovery, product
state placement and migration are still required. The API now has a separate
[development-only HTTP adapter](../README.md#development-file-service-configuration-api)
using this store. It is disabled by default, compiled only for Linux QEMU
development, restricted to loopback and never connected to activation. This
does not waive product state provisioning or power-loss qualification gates.
