<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors -->

# Retained disposable NFSD component

Available only with `qemu` (controller also requires Linux). This is one fixed
kernel component shared by two existing disposable guests, not the product NFS
backend, exclusive control-domain admission or complete stop authority.

`OpenCodeQEMU` requires root, ARMv5, VersatilePB and exactly the code fixture's
boot selector. `OpenRebootQEMU` requires the separate seed/verify state selector;
its trusted main-package wrapper additionally preserves the original synthetic
data-disk verification. Neither constructor accepts paths, commands, privilege
settings or replacement backends. Normal builds cannot import this package.

The component retains original NSFS network/mount references and the NFSD
control directory's filesystem/device/inode/unique-mount identity. Operations
serialize on a locked OS thread. Every bounded legacy transaction opens a new
file beneath that original directory, without symlink/magic-link/mount crossing;
seeking a reused control FD would return an old transaction snapshot.

Startup requires the exact v3-only empty profile, retains an IPv4 loopback
TCP/2049 socket, attaches its FD through portlist and starts two NFSD threads.
`CheckRunning` rechecks original authority, the exact profile and that retained
socket's original identity, actual address and accepting state. Stop attempts zero threads/socket
closure once and verifies the stopped profile; normal Close follows verified
consumer settlement. Copies/invalid handles refuse. Uncertain transactions or
closure retain review and original references; a second constructor cannot
erase the first lifetime. JSON is refused and formatting is private.

At allocation, a private read-only observation records SOCKFS device/inode and
the kernel's nonzero socket cookie, requiring IPv4 TCP and CLOEXEC. Identity is
rechecked around readiness observations, before attachment, after the running
profile, before the stop transaction and before socket close. Equal endpoints
alone cannot substitute for the original socket. Host tests use real sockets
to reject a replacement listener without changing it; valid ARMv5 fixtures and
clean synthetic reboot/teardown retain their existing contracts.

This is not an atomic FD-table lease or independent close authority. It does
not exclude unrelated concurrent descriptor-table writers, qualify controller-
level descriptor substitution/close faults, or admit cleanup of an allocated
but never-attached socket: Stop still refuses an unstarted controller. Such
partial-start settlement needs its own original-resource and uncertainty proof.

`CheckPreparedQEMU` is a distinct read-only observation of an original reserved
but never-started controller. It verifies held namespace/control references,
fresh empty-profile reads, the same process-local active reservation and an
empty retained-failure census. It performs no transaction writes, Stop,
Close, release, replacement or reset. An original controller remains prepared
before/after the optional second-constructor-refusal fixture while only that
server's acquired daemons are stopped. This is not OS-wide sole-domain authority.
Unsupported lifecycle observations refuse; reference/profile uncertainty retains
review and original references. Positive prepared observation is not stopped,
closed or release authority. General constructor/read/close/cancellation faults
and product integration remain unqualified.

The optional code guest composes this with original live rpcbind/mountd and
code/config/state/channel handles. It additionally requires accepted NFSv3 NULL
RPC and verifies both original daemons/channels before and after kernel checks.
Uncertain kernel settlement retains both daemon lifetimes until VM destruction.
It does not publish exports or grant data roots, assemble/mount disks, implement
NLM/NSM or qualify a real nfsowner backend. The separate reboot fixture preserves
its real synthetic I/O checks and independent read-only Netlink observations.

Sequential checks are not an atomic lease, full kernel cache/client census,
external-root exclusion, pending-I/O quiescence or product recovery. Product
namespace/privilege admission, complete faults, normal/unclean-boot service
reconstruction and physical EX4 qualification remain required. The controller
does not add automatic restart to a reviewed single-use Owner.
