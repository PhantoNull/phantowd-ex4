<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors -->

# Dedicated NFS runtime ownership

Status: proposed Owner contract; operator confirmation pending. This is not
an implemented privileged controller, product bootstrap or permission to operate
an existing NAS. Initial execution work is limited to disposable host/QEMU tests.

## Existing evidence and the missing boundary

The [clean-reboot fixture](QEMU-FAST-TESTS.md#separate-state-persistence-boots)
starts real NFSv3/TCP from retained synthetic policy in two independent kernels.
It proves normal access and teardown, not a fault-complete service Owner or
ordinary unclean-shutdown recovery. Its `nolock`/`soft` client settings are test
bounds, not product defaults or NLM/NSM recovery evidence.

The generic [process owner](../src/phantowd-api/internal/processowner/README.md)
owns userspace children. Its static/non-root launcher must not gain arbitrary
kernel controls, root commands or NFS authority. Kernel threads, exports,
listeners and mountd authorization/cache state require a separate owner.
Upstream documents kernel controls and the destructive effect of server shutdown
on lock/state; this is why stopping a PID is not a complete NFS stop.
[Kernel administrative-interface background, version6.9](https://docs.kernel.org/6.9/admin-guide/nfs/nfsd-admin-interfaces.html).
The exact pinned kernel/nfs-utils implementation must still be checked before
selecting a product control API; this older overview is not that qualification.

## Typed candidate: no execution authority

`Plan.NFSv3TCPCandidate` derives immutable configuration and requests from one
[complete file-service Plan](../src/phantowd-api/internal/fileserviceplan/README.md).
Each request binds export ID, relative path, complete observed logical-volume /
filesystem / mount / device tuple, requested RO role and every client rule.
The entire six-field policy/active/identity/storage freshness tuple is retained.
Input and returned client slices do not alias the candidate. JSON is refused.

An initialized empty export policy produces a bound disabled candidate with no
startup documents. Missing/invalid Plan is an error, never equivalent to disabled
or pristine state. Mixed RO/RW client rules need writable backing without
broadening the other clients or exports. Whole-volume `.` is not implicitly
reinterpreted as a Samba share-root request.

This initial candidate is TCP/NFSv3/AUTH_SYS only. Kerberos desired previews
remain supported by the general planner, but this profile refuses every GSS
flavor, including mixed policies, without changing it or falling back to `sys`.
Kerberos requires separate userspace/kernel integration, not another option in
the renderer. [Upstream RPCGSS support](https://docs.kernel.org/filesystems/nfs/rpc-server-gss.html).
IPv6, NFSv4, protected transport, NLM and NSM are independent qualification items;
the existence of a typed request does not qualify any of them.

The candidate does not retain owners or mount leases. `Build` accepts internal
snapshots; freshness equality is not provenance. A trusted runtime constructor
must rebuild/compare from the original policy, identity and storage owners,
never accept caller-supplied JSON or a prior boot's transient tuples.

## Proposed construction and sole ownership

- Fix the trusted kernel/backend implementation at construction. Operations take
  contexts, not replacement backends, executable paths, arguments or root lists.
- Admit one exclusive NFS control domain, with original network/control-filesystem
  namespace references and a complete export/listener/daemon census. Unknown
  existing resources refuse construction; do not adopt PIDs or stop foreign NFS.
  Product namespace placement and complete privilege/resource profile are open.
- Retain the original policy lease, qualified volume/root handles, code/loader
  closure, namespace references and applicable runtime/state resources. Numeric
  revision equality, path existence and `mountpoint=` are insufficient.
- Reuse the established storage-roster/member then identity planning lock order.
  Kernel/file/process operations must not run inside those derivation callbacks.
  Resolve the full policy/role/runtime lock graph before implementing mutations.
- Keep code/state/data roles separate. The NFS profile must validate its own
  dynamic executable/library closure; do not relax the static launcher or reuse
  the Samba privilege profile as NFS authority.
- Resolve relative paths under retained qualified roots, exclude symlinks and
  unexpected nested mounts, and preserve source permissions/ACLs. No automatic
  mkdir/chown/chmod, unmounted local fallback or legacy adoption during startup.
- Preserve stable fsid-to-source identity. Reusing an export ID for another
  filesystem/root is not an ordinary reload; old handles and consumers must be
  accounted for by a separately specified transition.

## Proposed lifecycle and failure matrix

The Owner is single-use within one admitted boot. It has no automatic restart
or reload loop. A future qualified boot coordinator implements the selected
[automatic recovery requirement](../STATE-OWNERSHIP.md#first-release-automatic-recovery-requirement)
with fresh authorities, not by reopening a reviewed instance.

| Event | Required outcome | Resource rule |
| --- | --- | --- |
| Missing/corrupt/foreign/pending or unqualified source | Refuse admission; preserve evidence | No kernel/service mutation or implicit writer recovery |
| Confirmed disabled candidate | No server startup | No synthetic success for a missing role |
| Confirmed enabled candidate | Revalidate all inputs, start once, verify actual RPC/export/root readiness and revalidate again | Retain original inputs throughout; process creation alone is not readiness |
| Partial startup or uncertain command | Review; one specified bounded compensation attempt | No blind replay, new active revision or authority release on unverified stop |
| Live input drift, lost source or unexpected service exit | Serialize withdrawal/stop, retain review | Restoration cannot revive the Owner; retain all uncertain consumers and their inputs |
| Accepted cancellation or explicit stop | Verify service settlement before input closure | An expired request context must not suppress required bounded cleanup |
| Failed/uncertain closure | Retained review | No retry on recycled descriptors, forced/lazy unmount or success from parent `Wait` alone |
| New boot after ordinary unclean shutdown | Fresh qualified reconstruction/recovery by boot coordinator | No old process/mount claims; routine manual confirmation is not the product design |

Stop proof must account for owned userspace descendants, exact export/cache and
listener state, kernel NFS activity and outstanding consumers. Zero thread count
or empty userspace export text alone is not a complete product quiescence proof.
Do not release policy/storage/code/namespace state while that outcome is unknown.
No API reports a requested revision active before the complete readiness boundary.

## Acceptance packets

1. Host Owner state machine: normal/disabled paths, fixed backend/inputs, no
   partial publication, cancellation and failed startup, drift/restoration,
   unexpected exit, uncertain stop/close and retained authority, concurrent
   operations and JSON refusal. Test behavior, not only call ordering.
2. Same-Plan handoff: trusted actual owners/leases, exact source tuples and client
   rules, missing/duplicate/changed roots, stale identity/policy/storage and fsid
   rebinding refusal. Keep complete constructor/rollback/close faults explicit.
3. Disposable ARMv5 kernel backend: actual RW/RO/UID/GID and denied clients,
   owned-daemon/kernel/export/source faults, bounded verified stop, no fallback
   data writes and no revival. Retain existing budgets; do not add default boots.
4. Product boot composition: complete role/installation/history provenance,
   normal and ordinary unclean boot, desired-disabled preservation, interrupted
   recovery at durable boundaries and real service access without manual enable.
5. Protocol and hardware release gates: NLM/NSM state and reclaim, reconnect /
   stale handles / rename / open I/O, multi-client and cross-protocol ACLs,
   qualified network/transports, efficient resource/throughput limits, actual
   EX4 storage/thermal/recovery and legacy migration. Do not equate QEMU with them.

Do not implement a production constructor from this proposal while namespace,
privilege, code/state ownership and complete boot/recovery contracts remain
unresolved. No HTTP activation endpoint, NAS operation or installer is added by
this packet.
