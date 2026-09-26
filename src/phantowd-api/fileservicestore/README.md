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
