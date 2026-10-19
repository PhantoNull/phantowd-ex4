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

That fixture also checks the pinned guest's kernel-control readback: `versions`
must be exactly NFSv3, `threads` must match its fixed two-thread running profile,
and `portlist` must contain exactly one TCP/2049 listener. Before startup and
after teardown it requires zero threads and an empty listener list. Each of the
three reads is capped at 4,097 bytes and unexpected/truncated profiles refuse.
The version/transport profile is rechecked after actual client I/O; the strict
two-boot receipt checker requires both profile and stopped-state evidence.

This is deliberately specific to the pinned QEMU kernel with NFSv2/v4 disabled,
not a general production-kernel parser. In Linux 6.18.55, `svc_one_xprt_name`
reports only transport and port: these checks cannot identify address/family,
export-cache completeness, remaining clients, NLM/NSM state or pending I/O.
Sequential readbacks are not an atomic retained service authority or complete
quiescence proof. No kernel control API, privilege or generic launcher is changed.

The generic [process owner](../src/phantowd-api/internal/processowner/README.md)
owns userspace children. Its static/non-root launcher must not gain arbitrary
kernel controls, root commands or NFS authority. Kernel threads, exports,
listeners and mountd authorization/cache state require a separate owner.
Upstream documents kernel controls and the destructive effect of server shutdown
on lock/state; this is why stopping a PID is not a complete NFS stop.
[Kernel administrative-interface background, version6.9](https://docs.kernel.org/6.9/admin-guide/nfs/nfsd-admin-interfaces.html).
The exact pinned kernel/nfs-utils implementation must still be checked before
selecting a product control API; this older overview is not that qualification.

## Pinned control-interface audit

Static inspection of Linux6.18.55 and nfs-utils2.8.6 establishes the constraints
below. Nine relevant built source files match the corresponding members of
the hash-verified upstream archives. This is source evidence, not a new kernel
execution, implemented backend or complete shutdown qualification.

| Interface | Observed behavior | Implementation consequence |
| --- | --- | --- |
| `nfsd` control filesystem | Its superblock is keyed to the network namespace captured by the filesystem context; final superblock teardown shuts down that namespace's NFSD threads | Retain the original namespace and control-filesystem authority; a path or mount in another namespace is not an interchangeable controller |
| Legacy `threads`, `versions`, `portlist` transaction files | The first read captures a response in the opened file's private transaction buffer; seeking does not request a new observation. A second transaction on the same open can return EBUSY | Retain a qualified directory/namespace, but open a fresh transaction file for every observation or command; do not repeatedly read a held snapshot as liveness proof |
| Legacy `portlist` | Reports transport and port, without address/family. Listeners may exist with zero NFSD threads | Zero threads cannot establish an unused control domain or complete stop |
| Generic Netlink `nfsd`, version1 | THREADS_GET, VERSION_GET and LISTENER_GET lack the administrative flag required by the corresponding SET operations; getters use the socket's network namespace | A fixed read-only observer is a candidate prerequisite, not permission to add SET commands or broaden an existing launcher |
| THREADS_GET | Repeats the thread attribute for each service pool; also returns grace, lease and private scope metadata | Bound and sum legitimate repeated pool counts; do not reject all repetition or expose raw scope data in HTTP |
| VERSION_GET | Returns supported major/minor pairs, with an empty enabled flag only when enabled | Preserve unsupported versus supported-disabled; reject duplicate pairs, malformed flags or incomplete results |
| LISTENER_GET | Returns repeated nested listener records with transport plus a full `sockaddr_storage` | Validate the exact address/family/port and nested record, not only the text `tcp 2049`; unsupported transport/address data must not become a partial positive result |
| Named Generic Netlink family lookup | Looking up a missing family by name can call `request_module` when module support is enabled | Read-only discovery must not send a name-based lookup that can autoload code. First enumerate registered families with a bounded complete controller dump, then use/recheck the observed ID |
| `rpc.nfsd` | If any listener is already present, it skips version/socket configuration and goes directly to the thread operation. Its legacy in-use helper treats an unreadable ports file as not in use | Command success or requested flags do not prove sole ownership, listener identity or the absence of foreign resources |

Each Netlink getter holds the NFSD mutex for its own response, not across the
three requests or subsequent startup. Error/overflow paths discard the reply;
they must remain unavailable, never an empty/disabled server. A matching sample
does not establish continued freshness, namespace provenance, export/cache
completeness, process ownership, NLM/NSM recovery or pending-I/O quiescence.

The selected cached kernel has NFSD built in, with v2/v4 disabled, but module
support remains enabled. The cached Buildroot nfs-utils recipe explicitly
disables `nfsdctl`; its source directory is not an installed executable. Do not
silently add that binary/libnl or change the runtime closure. A separate
QEMU-only observer now uses the existing syscall dependency; its implementation
and acceptance below are distinct from this earlier static source audit.

Relevant pinned sources: Linux `fs/nfsd/{nfsctl,nfssvc,netlink}.c`,
`net/sunrpc/svc_xprt.c`, `fs/libfs.c`, `net/netlink/genetlink.c` and
`include/uapi/linux/nfsd_netlink.h`; nfs-utils `utils/nfsd/{nfsd,nfssvc}.c`.
The Linux archive lock is in [versions.env](../versions.env); the selected
Buildroot nfs-utils recipe checks archive SHA256
`2bd7b34e809a7eff2f4bc5fc5fd96ebcd66a5458b471a270cbd2dc169b011550`.

## QEMU-only read-only kernel observation

The guarded NIC-less reboot fixture additionally samples registered families,
NFSD threads, versions and listener identities. Requests are fixed and contain
no attributes: controller discovery is a complete dump, not a name lookup;
only NFSD GET commands3/5/7 are encoded. The original network namespace is held
while one socket performs discovery, the three GETs and a confirming discovery.
Kernel sender, sequence, port, command/version, complete framing and bounds are
required. Descriptors close once; failed closure, changed namespace, cancellation
or an expired shared three-second observation budget cannot report success.

The exact running profile is v3-only, two threads summed across legitimate
pool attributes and one AF_INET/TCP listener at127.0.0.1:2049. Stopped requires
zero threads and no listeners. Duplicate/unknown/incomplete records, different
listener addresses, UDP/IPv6 or unsupported versions refuse this fixed fixture.
This does not disable IPv6 elsewhere or qualify a production protocol profile.
Catalogs cap at256families/1MiB, datagrams at64KiB and pool attributes at256;
private scope metadata is validated but not returned or logged.

The legacy control-file readbacks remain mandatory. Both checks run before
startup, after startup/client I/O and after stop. The existing phase/aggregate
receipt requires `listener_identity=true`; older text-profile-only receipts do
not establish it. No additional boot, installed package, capability or product
entry point is added. Samples are sequential, not atomic authority, a retained
service lease, export/cache completeness or proof of all outstanding I/O/NLM/
NSM state. The Owner contract remains proposed; host parser tests do not replace
the actual guest acceptance or qualify the full failure/closure matrix.

Local ARMv5 execution now passes the standard smoke and both independent
clean-state kernels with this mandatory listener-identity receipt, retaining
the original policy/data/inode and unchanged source witnesses and budgets.
Portable negative cases, scoped Linux race tests and strict receipt/routing
controls also pass. This is separate from the static source audit, full firmware
reproduction, ordinary unclean boot recovery or physical-hardware qualification.

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

0. Read-only kernel-observation prerequisite: fixed GET-only commands and a
   bounded complete registered-family census (no autoloading name lookup),
   original namespace lifetime, kernel sender/sequence/port correlation and
   complete reply settlement. Test legitimate pool repetition, nested listener
   identities, compiled/disabled versions, truncation, duplicates, unknown data,
   errors, cancellation and overflow without publishing partial observations.
   First execute in the existing disposable NFS guest: before/start/I/O/stop,
   requiring the actual loopback listener address as well as version/thread/
   transport state. No extra default boot, capability, mutation, HTTP or product
   constructor. This neither selects an execution backend nor approves the Owner.
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
