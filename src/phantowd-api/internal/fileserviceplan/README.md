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
  matching enabled Samba journal/passdb observation. NFS anonymous IDs must
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
