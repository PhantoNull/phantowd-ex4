<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors -->

# Retained NFSD component

`OpenLinux` accepts the original NFSD mount and current network and mount
namespace descriptors from a trusted platform owner. It keeps duplicates,
verifies the exact stopped profile and holds a protected `/run` flock until
verified closure. The platform establishes mount provenance and shares the
protected runtime directory among cooperating controllers. The controller
binds one admitted IPv4 address and reuses its original thread and socket
checks. This layer controls the kernel listener and threads. RPC helpers,
export policy and storage admission belong to the service runtime.

The existing QEMU entry points require Linux, root, ARMv5, VersatilePB and an
exact mutually exclusive boot selector. The guarded owner fixture also uses
`OpenLinux`, rejects swapped grants and a conflicting lock, closes its
original copies before starting, and stops and closes two successive kernel
lifetimes.

`OpenCodeQEMU` and `OpenRebootQEMU` preserve the original fixture admissions.
`OpenSmokeQEMU` admits only `phantowd_nfs_kernel_smoke=1`. No constructor
accepts a caller-selected path, command, privilege or replacement backend.

`OpenPeerQEMU` additionally admits only `phantowd_nfs_peer=server`, with a fixed
wildcard listener inside two isolated guests. The mutually exclusive client role
cannot open the controller. A private inherited Unix socketpair connects their
NICs; no host listener, user networking or LAN forwarding is used. The real
client verifies NFSv3/TCP bytes, fsync and unmount before clean controller stop.

The controller retains original NSFS network/mount references and the NFSD
control directory's filesystem/device/inode/unique-mount identity. Operations
serialize on a locked OS thread. Each bounded control transaction opens a new
file beneath that original directory, without symlink or mount traversal;
reusing a transaction FD would read a stale snapshot.

Startup requires the exact v3-only empty profile. It retains its own IPv4
loopback TCP/2049 socket, attaches that FD through `portlist` and starts two
NFSD threads. Socket cookie and SOCKFS identity accompany address/listening
checks. Stop writes zero threads once, closes that original socket once and
checks the empty profile. Close follows verified stop. Copies, invalid handles
and uncertain transactions refuse; review and original references are retained.
This process-local reservation does not establish OS-wide exclusivity.

The baseline smoke now uses this controller after settling the stock guest
service. A fixed Go fixture starts tracked foreground rpcbind/mountd children,
exports synthetic data with all-squash, mounts NFSv3/TCP through loopback,
checks server-to-client bytes, fsyncs a client write and verifies both views.
It unmounts and withdraws the export, verifies controller stop and reaps both
children before emitting `kernel_backend=true activation=true teardown=clean`.
The shell does not implement a parallel NFSD startup. Its `rpc.nfsd 0` call
settles only the inherited stock service before controller admission.

The smoke performs two fixed complete lifetimes, not a retry: a fresh controller
and client mount read the previous client's fsynced bytes, then write and verify
new bytes. Only verified stop and closure of every original reference release
the process reservation. Uncertain disposal retains it. Calls through the old
closed handle refuse without poisoning the new lifetime. Both cycles must
finish before the restart assertion is emitted; failure never starts a retry.

The fixture's soft/nolock mount is bounded disposable testing, not product
mount policy or NLM/NSM qualification. It does not qualify production code,
configuration/state owners, external clients, crash recovery, pending-I/O faults,
complete kernel export/client census, physical EX4 hardware or installation.
Historical optional callers from the source branch are not ported or claimed
qualified here. Existing socket/profile/refusal tests accompany the port.
