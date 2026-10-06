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

## Reader-bound observation recheck contract (before implementation)

1. **Input/authority:** only a Snapshot produced by this still-open Reader,
   with private reader provenance and file/directory identity metadata. No
   caller path, owner, alternate scanner, state writer or stronger schema.
2. **Transition:** serialize recheck with Read/Close; validate the prior origin
   before file I/O, reread using the same protected descriptor/lock/bounds and
   compare full claims and identity/content metadata, excluding atime only.
   Retain one nonblocking, close-on-exec inotify descriptor watching the
   already-owned directory via its fixed `/proc/self/fd/<fd>` anchor. Bound
   event draining to64KiB per observation; mutation events advance a private
   generation. Watch loss, malformed events, overflow or exhausted drain budget
   permanently invalidate this Reader until explicit close/new construction.
   Kernel inotify and trusted real procfs are prerequisites; no fallback watcher,
   pathname discovery or silent metadata-only downgrade is allowed.
   Success describes this bounded read, never continued freshness or a lease.
3. **Failure:** zero/foreign/canceled/closed input or missing/replaced/rewritten/
   relinked/mode/owner/directory drift returns the existing redacted error.
   Restored bytes or revision alone cannot rehabilitate an earlier observation;
   there is no retry, repair, automatic adoption or sticky-Owner reset.
4. **Boundary:** internal Linux reader only, with private cross-platform snapshot
   provenance. No JSON/HTTP, product wiring, persisted identity, mount/import,
   daemon activation, new privilege or hardware operation. Claims remain
   independent point-in-time data even after reader close.
   Repeated actual tmpfs tests showed same-byte/permission/directory ABA can
   preserve every timestamp; metadata alone is explicitly insufficient.
   The watch is a loss-detecting local observation, not global exclusivity or
   immunity to privileged namespace/observer manipulation.
5. **Acceptance:** native real-files tests for stable/cross-reader/reopen/close,
   changes at equal revision, same-byte replacement/restoration, directory ABA,
   metadata/contents racing during recheck and serialized concurrency. Existing
   disposable ARMv5 registry fixture checks stable and restored-old refusal;
   Windows preflight, pinned Linux race and actual standard/two-boot overlay.
   Reuse fixed caches/volumes; create no persistent image or volume.

The metadata-only candidate reproduced rapid rewrite/permission/directory
restoration with identical full stamps and claims in ten native repetitions.
The retained mutation watcher fixes those regressions without sleeps or retries.
Ten repeated pinned Linux race runs and whole tagged API vet/race pass, including
actual lost-watch/descriptor flags, bounded synthetic event records/drain budget,
generation-overflow and lifecycle/provenance refusal tests. Windows DOM/vet/unit
and ARMv5 cross-build pass; the actual ARMv5 standard fixture verifies stable
recheck and old-snapshot refusal after permission/same-byte restoration, followed
by clean two-boot state acceptance. Eight source hashes and seven original base
artifact hashes agree. This cached overlay does not regenerate SBOM/legal-info,
qualify a clean/hosted build or authorize physical storage/service operations.

The kernel queue and trusted procfs are part of this observation boundary.
Overflow/watch loss/drain exhaustion is a permanent Reader error, not an
automatic rescan. Actual kernel queue overflow is not independently induced;
the native overflow-record and bounded-drain sources are test-only. There is
one additional private watch descriptor per Reader, no background worker and
at most64KiB event reads per observation. Data remains point-in-time: privileged
observer/namespace manipulation and global-use qualification are out of scope.

## Registry/census composition contract (before implementation)

1. **Input/authority:** one still-open protected Reader, a validated combined
   desired policy and the trusted complete sysfs/proc readers. A private Linux
   collector takes no prior caller snapshot, chosen root subset or request path.
   Callers must own the policy slices and not mutate them during collection.
2. **Transition:** observe registry, collect the entire mounted-ext census and
   compute the existing private policy/backing reviews from that same pair.
   Recheck the whole census, then recheck the original registry on its same
   Reader before returning. Preserve separate revisions and scoped uncertainty.
3. **Failure:** invalid input/cancellation, reader closure, any collection or
   recheck uncertainty returns one redacted error and a zero composite result.
   No retry, partial publication, automatic restore/adoption or source fallback.
4. **Boundary:** read-only internal composition, not an atomic global snapshot,
   continued freshness, lease, compatibility qualifier or planner/activation
   authority. Existing pure reviewers retain their point-in-time contract.
   No registry writer, product wiring, HTTP, mount/import or new privilege.
5. **Acceptance:** native real registry plus existing complete synthetic census
   exercises stable/empty/unknown/conflict, early refusal and restored registry,
   root and unclaimed/excluded census drift, without partial results. Actual
   ARMv5 existing disposable MD/tmpfs fixture exercises the composed fixed
   reader and same-byte registry restoration during collection. Whole Windows,
   native tagged race and standard/two-boot overlay; no persistent Docker input.

The composition passes whole Windows preflight/cross-build, pinned Linux tagged
vet/race and actual ARMv5 standard/two-boot overlay. Native real registry files
exercise restoration during the first and second census, directory ABA, reader
closure, cancellation, early refusal and root/excluded/unclaimed scope drift;
zero composite output is mandatory on failure. The existing actual ARMv5 MD
fixture confirms separate policy/registry revisions and missing-unselected
backing, and restores its tmpfs registry during the second complete census:
no review escapes. Original base artifacts remain unchanged. Kernel census
observations remain sequential and namespace-scoped; this is not a product
authority, event history for kernel topology or independent clean qualification.
