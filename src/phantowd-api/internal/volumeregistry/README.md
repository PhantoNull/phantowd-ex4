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

## Policy-binding follow-up contract (before implementation)

1. **Input/authority:** validated combined SMB/NFS desired configuration,
   protected registry Snapshot and complete mounted-ext census. Entirely private
   pure computation, no path/owner/runtime authority and no HTTP wiring.
2. **Transition:** keep policy and registry revisions separate; require exact
   logical-ID/expected-UUID agreement before copying scoped observations for a
   desired volume. Count SMB/NFS references without changing either document.
3. **Failure:** reject invalid/split-revision policy or incomplete whole census,
   even for empty desired volumes. Unknown IDs stay not-registered, conflicting
   expected UUIDs stay registry-policy-conflict; never rebind by UUID alone.
   Missing/cloned/unresolved observed backing remains explicit, not usable.
4. **Boundary:** extend the existing private main-package registry reviewer and
   reuse fileservice.Config validation; no second policy owner or scanner,
   registry writer, adoption, lease, planner input or activation.
5. **Acceptance:** native exact-match/unknown/conflict/revision/order/reference/
   clone/partial/empty16-volume tests; existing ARMv5 tmpfs/MD fixture exercises
   actual protected snapshot plus combined policy and conflict refusal. Whole
   Windows/Linux/standard/two-boot validation, unchanged base and no new volumes.

The policy-binding follow-up passes whole local Windows/Linux tagged race and
actual ARMv5 standard/two-boot tests. Its required guest marker verifies separate
registry/policy revisions, exact ID+UUID agreement, unknown-ID/conflicting-UUID/
split-policy refusal and one SMB/NFS reference each. Native tests also cover
aliases/clones, unresolved disk evidence, malformed unclaimed census, ordering,
explicit empty policy and16-volume bounds. A registered volume is unreferenced
only when its ID is absent from the desired volume dictionary; protocol counts
do not imply activation or that referenced paths exist. No future registration
writer or service Owner is created by this observation.

## Scoped backing-topology follow-up contract (before implementation)

1. **Input/authority:** the existing protected Snapshot and complete mounted-ext
   census only. Reuse their validation before examining any registered subset.
   Keep schema1 unchanged; do not introduce expected physical/MD identifiers.
2. **Transition:** pure private observation of each uniquely matched filesystem's
   immediate source kind, physical leaf count and MD-array count. Distinguish
   physical disk/partition, MD device/partition/other MD-backed stack and other
   block stacks. Aliases of one kernel object are not extra backing objects.
3. **Failure:** invalid whole census/snapshot returns no partial result. Missing
   or cloned filesystem claims receive no selected backing. Unresolved disk
   evidence stays explicit even when topology can be observed; a topology name
   is not identity qualification, health, compatibility or activation readiness.
4. **Boundary:** private main-package computation, no I/O, additional scanner,
   raw identifier/path/device output, persistence, schema migration, public API,
   Owner, mount/import, service activation or hardware work. This prepares a
   later reviewed stronger-backing contract; it does not implement that contract.
5. **Acceptance:** native complete-census cases for direct disk/partition, MD,
   stacked backing, aliases/clones/missing/unresolved/empty, order, immutable
   inputs and JSON refusal. Reuse the existing actual ARMv5 disposable MD
   fixture with a mandatory consumer assertion; run Windows preflight then
   bounded full native race and standard/two-boot overlay, without new volumes.

The scoped topology review passes complete pinned native tagged vet/race and
actual ARMv5 standard/two-boot overlay. Native tests distinguish all six source
classes, retain unresolved VPD evidence, reject malformed unclaimed census and
zero Snapshot, and cover alias/clone/missing/empty/order/result ownership and16
claims. The required guest assertion observes the actual disposable MD device,
two physical leaves and one array without selecting a missing claim. Original
base hashes remain unchanged; no project test container survives. This is not
a stronger persistent identity selector, independent clean-build qualification,
physical-media compatibility or service authority.
