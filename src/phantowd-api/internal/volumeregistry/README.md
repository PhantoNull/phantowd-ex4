# Internal volume registry observation (M3.2g)

## Task contract (before implementation)

1. **Input/authority:** a bounded versioned document holds explicit logical
   VolumeID/expected-filesystem-UUID claims. Reuse `shareconfig` validation and
   `configjson`; do not derive IDs or copy WD formats. The Linux reader takes a
   borrowed trusted directory descriptor under trusted parents, owned by its
   effective UID with mode0700. Bind that UID once at construction. Fixed
   `volumes.json` only; regular single-link0600 file, same filesystem, no
   symlink/magic-link fallback. Root-owned product provisioning is not wired.
2. **Transition:** read-only document observation, then pure scoped reconciliation
   against the complete validated mounted-ext census. Read retains its own
   directory descriptor/shared nonblocking flock, serializes Read/Close and
   brackets file/directory metadata. All eventual writers must honor the same
   directory lock; privileged noncooperating writers are outside this contract.
   A snapshot is point-in-time provenance, not adoption/freshness/qualification.
3. **Failure:** missing, unsafe, corrupt, oversized, duplicate, unsupported,
   concurrent writer/metadata change or close uncertainty yields a redacted
   error and no partial snapshot. No repair, retry, initialization or fallback.
   Resolver refuses incomplete whole census; absent/cloned matches stay
   unusable and expose no selected path or activation token.
4. **Boundary:** one internal package for the document and Linux protected
   reader; private main-package resolver reuses the existing scoped review,
   not a second storage scanner. No writer, state placement, registration,
   import/mount, HTTP, Owner construction, service activation or NAS changes.
   UUID-only claims do not establish durable physical identity/WD compatibility;
   GPT/MD/global-use qualification remains a separate prerequisite.
5. **Acceptance:** strict model tests (missing/null/duplicate/unknown/trailing,
   invalid IDs/UUIDs,16-entry bound); native Linux reader tests (permissions,
   links/FIFO/oversize, metadata drift, lock, descriptor ownership/close);
   complete resolver tests (aliases/clones/missing/invalid/unclaimed inputs);
   actual ARMv5 QEMU tmpfs registry plus existing disposable MD census.
   Windows preflight before bounded Linux race and standard/two-boot overlay.
   No new image/volume, physical media or flash qualification.

## Current acceptance and next dependency

Windows model/preflight and actual pinned Go1.26.6 Linux tagged vet/race pass.
Native tests exercise real unsafe entries, replacement/deletion/chmod/link/
rewrite/directory drift, cancellation, shared-lock exclusion, borrowed-descriptor
closure and concurrent reads. Non-root native tests skip chown-only cases;
actual root ARMv5 QEMU separately refuses a foreign file owner and unsafe mode,
reconciles actual disposable MD plus an absent UUID and completes standard
smoke/two-boot fixtures. The fixed smoke contract requires the registry marker.
Seven base artifacts remain unchanged. No product writer or state is created.

This schema is intentionally incomplete for durable backing identity: UUID
claims and namespace-scoped uniqueness cannot qualify import/mount or service
activation. Explicit recoverable registration/retired IDs, stronger GPT/MD/
physical bindings, global-use accounting, compatibility and product-owned
state/bootstrap remain necessary. Snapshot lifetime does not imply reader or
kernel freshness; close does not retroactively invalidate point-in-time data.
