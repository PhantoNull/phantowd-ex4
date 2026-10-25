<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors -->

# Retained disposable NFSD component

Ported from `fix/api-plaintext-listener-guard` at `17f929f`: ten existing
files, adapted to the current integration tree. This package is available only
with `qemu`; its controller additionally requires Linux, root, ARMv5,
VersatilePB and one exact, mutually exclusive boot selector. Normal builds do
not include it. It is not a production NFS backend or appliance activation.

`OpenCodeQEMU` and `OpenRebootQEMU` preserve the original fixture admissions.
`OpenSmokeQEMU` admits only `phantowd_nfs_kernel_smoke=1`. No constructor
accepts a caller-selected path, command, privilege or replacement backend.

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
