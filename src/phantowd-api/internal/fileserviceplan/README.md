# Internal file-service candidate plan

This package is an incomplete M4.1 prototype. It accepts a validated combined
SMB/NFS policy plus explicit identity and storage snapshots, checks that the
required accounts and mounted logical volumes are internally consistent, and
produces deterministic daemon-configuration candidates bound to desired and
active service revisions, identity generation/evidence fingerprint, and
storage generation/canonical volume-set fingerprint.

## Safety boundary

- The package has no filesystem, process, HTTP, mount or daemon-control code.
- `Build` still accepts snapshots from its internal caller and is not a
  capability boundary. On Linux, `IdentityFromOwner` obtains the latest
  all-or-error `identityowner.Owner.FileServiceSnapshot` and maps its complete
  identity evidence into a planner snapshot. The local ARMv5 QEMU Owner fixture
  exercises this adapter and invalidates an old candidate after a registry
  transition. That integration intentionally uses an empty policy and
  synthetic empty storage. A separate Linux-only QEMU fixture uses the actual
  mount tuple observed by the internal mount owner for one disposable ext2
  volume to build a non-empty candidate; identity remains synthetic in that
  fixture. It does not use a trusted production storage provider or connect the
  candidate to product service lifecycle.
  A third, separate fixture composes the disposable Owner identity/local
  UID/GID evidence with the mount-owner tuple for an NFS-only read-only
  candidate; stale identity and mount fingerprints are refused, with no
  Samba enrollment or export activation. Storage now comes through
  `StorageFromMountedOwnerSet`, which accepts only non-serializable evidence
  collected from every Owner in a fixed roster while all member locks are
  held. Its owner fingerprint is included in planner freshness. The QEMU
  roster has one synthetic volume; this does not provide a production roster
  source or prove physical inventory completeness. `BuildFromOwners` now
  holds the mounted roster/member locks first and then the identity Owner lock
  while adapting both snapshots and building one candidate. Only deterministic
  in-memory work runs under both locks; the function returns no apply or
  activation capability. The ARMv5 fixture checks this ordered composition
  with redacted Owner/passdb evidence and one synthetic mounted volume; its
  NFS-only policy has no Samba share section.
- Required volumes must be uniquely mapped, filesystem-UUID matched, mounted
  at the fixed logical anchor, marked qualified, and writable when policy
  requests writes. SMB grants must resolve to an enabled native account and a
  matching enabled Samba journal/passdb observation, with the exact UID and
  primary GID present in the supplied Unix census even for SMB-only policy.
  NFS anonymous IDs must
  exist in the supplied Unix UID/GID census.
- Identity freshness compares both registry revision and the SHA-256 evidence
  fingerprint (native/Samba journals, local reservations and observed passdb);
  `FreshAgainst` remains an equality check, not an atomic lease. A future owner
  must recollect all evidence immediately before any transaction and close
  intervening races. Storage freshness likewise includes a canonical SHA-256
  fingerprint over the sorted complete volume set in addition to its generation;
  changing a mount ID or device tuple while reusing the generation invalidates
  an existing candidate. Enumeration order does not affect the fingerprint.
- Returned Samba/NFS text is candidate output only. This package itself does
  not run native `testparm`/`exportfs`, write a live file, or claim a service
  revision is applied or runtime-validated. A separate local ARMv5 QEMU
  integration fixture validates the combined SMB candidate using target
  `testparm` and the mount-owner-observed synthetic volume tuple. A separate
  `exportfs` fixture validates and withdraws the NFS candidate using synthetic
  snapshots on the disposable guest volume. Another fixture sends the
  Owner-backed NFS-only candidate through target `exportfs`: it uses one fixed
  guest export file, checks the read-only/squash/UID/GID/fsid rule and
  pre-existing exports, then withdraws it and requires the baseline table to be
  restored. These are parser tests only; neither is product-owner validation
  or activation.
- `Plan`, `Freshness`, `IdentitySnapshot`, and `StorageSnapshot` reject JSON
  marshaling and unmarshaling. There is deliberately no apply/activate
  operation and no product HTTP exposure.

## Candidate Samba NSS

`Plan.SambaNSSCandidates` returns deterministic passwd/group/nsswitch documents
bound to the existing plan freshness tuple. The zero/refused plan returns an
error with no partial document. Only enabled, granted, confirmed Samba accounts
are rendered; native same-number private groups are preserved. No unrelated
host users, imported identities, supplementary/shared groups or credentials are
copied. Disabled/ungranted/retired rows remain absent without discarding their
permanent registry reservations. Enumeration order does not affect output.

Fixed locked root and nobody lookup rows are separate from SMB grants. Their
names are already reserved by the registry; a `nogroup` baseline is deliberately
not invented because that name is legal for a managed private identity. All
password fields are fixed `!` sentinels, home is `/`, shell is `/sbin/nologin`,
and NSS sources are files-only. No shadow file, home or Unix login is created.
Combined candidate text is bounded to 32 KiB and at most 128 granted accounts;
the eventual constructor must separately enforce its full configuration budget.

On Linux, `BuildFromOwners` derives these same candidates under the ordered
mounted-roster/identity locks. A disposable ARMv5 fixture uses the actual
Owner-managed Unix/passdb observations and mounted roster, independently parses
and assesses the documents, refuses missing UID/GID evidence, and round-trips
desired native state without changing native/Samba journals or passdb identity.
Old freshness and disabled desired grants are refused after the transition.
The documents are **not installed or used by the running Samba daemon**. This
does not provide a consumer lease, native libc NSS qualification, same-passdb
state binding, revocation coordination or product service activation.

## Isolated share-root candidates

`Plan.SambaShareCandidates` returns deterministic share sections at fixed
`/shares/<share-id>` destinations together with the exact logical-volume and
relative-subdirectory requests from that same Plan. Source policy, including
nested grant slices, is privately copied at Build; changing caller inputs or
returned root requests cannot change this candidate. Existing ordinary previews
remain unchanged. The candidate shares the Plan's complete identity/storage
freshness tuple and NSS documents, but **does not retain those authorities**.

The renderer preserves exact RO/RW user lists and denies guests, symlink
following and wide links. A root is marked read-only only when that share has
no RW grant; a writer on another share never broadens it. Mixed shares need a
writable clone with independently qualified Samba and Unix/ACL enforcement.
Whole-volume `.` requests are refused by this isolated path, consistently with
the existing mount handoff; an ordinary desired preview may still describe them.
Zero/refused candidates return no partial sections or root requests. An NFS-only
Plan produces an empty SMB request set, not a synthetic share.

This is a preparation step, not the completed storage-to-native-Samba path.
The next coordinator must acquire/revalidate the complete mounted roster,
retain exact declared directory descriptors, attach only those roots inside
Samba's restricted namespace and retain storage through verified descendant
stop and input closure. It must not fall back to ordinary host-volume paths.
Storage verification must remain outside recursive identity/backend/runtime
locks. No daemon consumes this candidate yet; full runtime-profile validation, real
RW/RO file-access proofs, source-loss quarantine and uncertain teardown are
still required. A local ARMv5 one-boot overlay does check the isolated request
against the live synthetic mounted-roster tuple and validates its sections with
target `testparm`; identity in that fixture remains synthetic. It provides no
Samba data handoff or access proof through this candidate. No new HTTP operation,
product startup or NAS write is added.

## Complete isolated candidate and declared-root comparison

`Plan.SambaIsolatedCandidate` packages private NSS, isolated share/grant text,
exact logical-volume/subdirectory/RO requests and all six freshness fields from
one complete Plan. It is immutable and non-serializable; returned root slices
are independent copies. Zero, unsupported whole-volume and NFS-only plans do
not produce a usable SMB candidate or partial documents. The existing separate
preview methods remain unchanged.

The QEMU-only `VerifySharePinsQEMU` adapter compares those requests with a live
trusted handoff's complete declaration. Its `VerifyDeclaredRoots` operation
checks original pins and rejects changed share IDs, volumes, paths, RO roles,
missing/extra/duplicate roots, without invalidating healthy pins merely because
the caller supplied a different declaration. Actual source loss still enters
sticky review; supplying matching policy after restoration cannot revive it.

Host tests cover candidate identity/storage/revision binding, caller independence,
JSON refusals and missing-authority refusal. Linux tagged race/vet pass. The
focused ARMv5 service campaign verifies exact/mismatching declarations against
actual mounted pins and source-loss/restoration behavior. This is **not** a
positive end-to-end Owner/Plan/candidate/native-daemon proof: complete identity
and storage freshness, retained lifetime, planned runtime configuration and
verified service settlement must still compose under the SAME service Owner.
No HTTP, product activation or real-disk operation is introduced.

## Native lookup before Samba enrollment

`SambaEnrollmentLookupFromOwner(ctx, owner)` is a separate Linux-only internal
constructor, not `Build`, `Plan` or `IdentitySnapshot`. It derives bounded
passwd/group/nsswitch candidates from the Owner's fresh native-only observation
under the mutation lock, including confirmed desired-disabled accounts before
passdb enrollment. It does not query a credential backend or fabricate
passdb-absence, SID or enabled-journal evidence.

The immutable `SambaEnrollmentLookup` exposes `LookupDocuments` and its source
`Fingerprint`; zero/error cases yield no documents. It rejects JSON in both
directions. Rendering shares the active planner's locked, files-only private
identity grammar and 32 KiB/128-account limits, but has a separate admission
contract. No unrelated/imported users, shadow data or supplementary groups are
copied; rendering does not reorder the source registry.

The existing `Plan` still requires enabled, granted accounts and corroborated
live passdb evidence. Enrollment lookup cannot substitute for service evidence,
authorize a mount/share/login or be passed as a Plan. These documents are not
installed, consumed by libc or bound to the running Samba daemon. A future
constructor must qualify fresh same-object configuration/state and retained
identity/storage ownership without holding the pure callback across I/O.

## Remaining M4.1 work

The identity Owner evidence adapter is host-tested and exercised in ARMv5 QEMU
with a disposable Owner and passdb backend. A separate QEMU fixture now builds
a non-empty plan from a live mount-owner fixed-roster snapshot for one
synthetic ext2 volume. `StorageFromMountedOwnerSet` adapts its non-serializable
all-owner observation and binds the roster fingerprint/generation into planner
freshness. It does not qualify real mounted volumes or establish that the
declared roster covers all appliance storage. The production M3.3 discovery to
logical-volume/compatibility roster source and persistent M3.4 Owner startup
remain absent. The product service owner must integrate the
pinned native parsers transactionally, preserve last-known-good configuration
on any failure, and recheck policy, active revision, identity and mount state at
the handoff boundary. Mount/path lifetime, process supervision, failure/reboot
semantics and data preservation remain separate M4.2/M4.4/M4.5/M4.6 gates.

The ARMv5 smoke additionally composes Owner-backed identity and the complete
one-volume fixture roster in a read-only NFS candidate and rejects altered
identity/storage freshness. A separate QEMU-only step briefly loads that exact
candidate with target `exportfs`, validates the parsed rule, removes only its
fixed export file, and confirms the prior table is restored. That integration
is still bound only to synthetic fixture inputs; it does not mint a product
roster, persist daemon configuration or activate a product service.

See the [implementation](plan.go), its
[synthetic ARMv5 fixture](../../file_service_plan_qemu.go), and
[M4 in the roadmap](../../../../ROADMAP.md#m4-supervised-smb-and-nfs).
