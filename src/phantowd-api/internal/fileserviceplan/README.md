# Internal file-service candidate plan

This package is an incomplete M4.1 prototype. It accepts a validated combined
SMB/NFS policy plus explicit identity and storage snapshots, checks that the
required accounts and mounted logical volumes are internally consistent, and
produces deterministic daemon-configuration candidates bound to four revision
values: desired policy, currently active policy, identity census and storage
snapshot.

## Safety boundary

- The package has no filesystem, process, HTTP, mount or daemon-control code.
- `Build` trusts its callers to obtain complete snapshots from the eventual
  identity/storage owners. The current QEMU fixture creates synthetic
  snapshots in memory; it proves planner behavior, not snapshot provenance.
- Required volumes must be uniquely mapped, filesystem-UUID matched, mounted
  at the fixed logical anchor, marked qualified, and writable when policy
  requests writes. SMB grants must resolve to an enabled native account and a
  matching enabled Samba journal/passdb observation. NFS anonymous IDs must
  exist in the supplied Unix UID/GID census.
- `FreshAgainst` is an equality check over revisions/generations, not an atomic
  lease. A future owner must recheck immediately before any transaction and
  close intervening races.
- Returned Samba/NFS text is candidate output only. This package itself does
  not run native `testparm`/`exportfs`, write a live file, or claim a service
  revision is applied or runtime-validated. A separate local ARMv5 QEMU
  integration fixture feeds the combined candidates to those target parsers;
  it uses a private temporary Samba file and a short-lived NFS export on a
  disposable synthetic guest volume, then withdraws that export. This is not
  product-owner validation or activation.
- `Plan` rejects JSON marshaling and unmarshaling. There is deliberately no
  apply/activate operation and no product HTTP exposure.

## Remaining M4.1 work

Trusted M3.4 storage and M2 identity providers must produce complete,
generation-bound observations. The product service owner must integrate the
pinned native parsers transactionally, preserve last-known-good configuration
on any failure, and recheck policy, active revision, identity and mount state at
the handoff boundary. Mount/path lifetime, process supervision, failure/reboot
semantics and data preservation remain separate M4.2/M4.4/M4.5/M4.6 gates.

See the [implementation](plan.go), its
[synthetic ARMv5 fixture](../../file_service_plan_qemu.go), and
[M4 in the roadmap](../../../../ROADMAP.md#m4-supervised-smb-and-nfs).
