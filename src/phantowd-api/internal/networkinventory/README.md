<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors -->

# Private kernel interface observation — M6.1b task contract

## Input and authority

Linux-only fixed collector uses bounded RTM_GETLINK/RTM_GETADDR netlink dumps
and fixed `/proc/thread-self/ns/net` namespace metadata. No user path, interface
selector, HTTP endpoint, mutation, subprocess, NET_ADMIN or namespace switch.
The desired parser remains `internal/networkpolicy`; this is a separate trusted
kernel-observation boundary, not another policy parser or authority.

Lock the calling goroutine to its OS thread during collection and pin that
thread's network namespace read-only/CLOEXEC until the operation finishes.
Observe all returned interfaces (including loopback/virtual/down) and IP addresses,
not just proposed ports. Bound interface/address counts and validate shape,
index/name uniqueness, MAC length and canonical prefixes. Keep kernel names,
current MACs and addresses private; JSON is refused. Summary returns counts only.
Current MAC is neither factory identity nor proof of a physical socket.

## State, failure and resources

Use one private unprivileged NETLINK_ROUTE socket, no multicast subscriptions,
fixed dump-only requests, kernel sender/sequence/port verification, explicit
multipart completion/status and refusal of interrupted/filtered/truncated dumps.
The standard Go net.Interfaces path does not surface dump-interruption flags or
address state; it cannot establish this contract. The bounded parser is private
and uses native-endian checked lengths, never unsafe casts.

Take two complete normalized link/address sets with namespace checks between/after; require
exact equality independent of order. No retry hides changing or incomplete
observations. Kernel errors, invalid/truncated shape, namespace drift, cancellation
or uncertain close produce no observation and a constant redacted error.
Namespace/socket descriptors are operation-owned; release is attempted once on
every exit path. An uncertain close refuses the observation, without retrying
the descriptor number or claiming confirmed release.

The result is immutable private point-in-time evidence. Recheck collects anew
and refuses a different namespace/interface/address set; it does not reset or
manage an Owner's review state. Missing/forged/copied observations are refused.
Caller must separately own any sticky review and transaction lifecycle.

Two matching samples are NOT an atomic netlink transaction, event subscription,
interface generation lease or proof against remove/re-add/ABA. Ifindex, name and
current MAC are transient. Standard address dumps do not qualify tentative/DAD
states as usability: address flags/scope/point-to-point peers are retained, but
no DAD admission, external address conflict, route, DNS or management reachability
decision follows. Nonblocking receive/poll has a five-second total socket budget
and cancellation checks; synchronous proc/open/send calls are not forcibly
interruptible. No automatic dump retry or partial-result success.

## Acceptance and remaining gates

Generated unit fixtures: ordering, duplicate/malformed interface identities and
prefixes, missing/incomplete address reads, between-dump drift, namespace change,
cancellation, reader errors, JSON refusal and resource cleanup. Linux native:
actual unprivileged namespace/interface capture and repeat observation.
ARMv5 QEMU: actual kernel collection, redacted counts, forged/serialization
refusal in the existing boot. No new stage, privileged host namespace or device.

M6.1 still requires qualified EX4 slot/factory-identity bindings, kernel address
state/route observation, global-use/conflict policy and freshness authority.
M6.2 persistent trial/confirmation/rollback remains required before applying
network policy. NAS/physical NIC, HDD/NAND and product startup are excluded.
