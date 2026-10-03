<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors -->

# Private kernel network observation — M6.1b/M6.1c task contract

## M6.1c configured-route observation

Extend the SAME collector/socket/namespace checks with a fixed strict
RTM_GETROUTE dump of configured IPv4/IPv6 FIB entries in all returned tables,
in each of the two samples. Cached route exceptions are not included. No route
lookup/selection, rule dump, network mutation, public input or new privilege.
Keep table/protocol/scope/type/TOS/flags, destination/source prefixes, metric,
input/output interface, gateway/preferred source and bounded ECMP members
private; correlate referenced local interfaces against the complete link set.
Nexthop-object IDs and unimplemented attributes remain explicitly unresolved,
never silently treated as simple usable gateways. Summary adds route and
unresolved-semantics counts only; existing JSON refusal remains.

Bound routes to 512 and ECMP members to 32 per route, keeping existing byte/time
budgets. Observe all returned table entries, including local/broadcast and
terminal routes; no main-table-only shortcut. Checked prefixes, attribute
lengths/duplicates, scalar bounds, via-family and nexthop framing fail closed.
Normalize dump order/ECMP member order; reject exact duplicates and between-
sample route drift. Preserve a canonical private digest of non-lifetime
attributes so unimplemented semantic changes are not discarded. Kernel cache
usage/expiry counters are excluded from equality; cache error is retained.
Matching samples are not atomic, freshness/expiry authority or policy routing
evaluation. Rules, referenced nexthop/encapsulation objects and reachability
remain separate admission prerequisites.

The initial unfiltered-dump proposal was corrected before qualification:
the actual native kernel returns `NLM_F_MULTI|NLM_F_DUMP_FILTERED` for IPv6.
Pinned Linux `ip_valid_fib_dump_req` excludes cached exceptions under strict
zero-flag requests; `rt6_dump_route` explicitly marks that scope FILTERED.
Only this fixed strict configured-route query allows that bit (including its
completion); link/address and undeclared route dumps still refuse it. No caller
can choose table/interface/protocol selectors. Interrupted dumps remain refused.
See [Linux 6.18.54 route dump implementation](https://github.com/gregkh/linux/blob/v6.18.54/net/ipv6/route.c)
and [UAPI framing](https://github.com/gregkh/linux/blob/v6.18.54/include/uapi/linux/rtnetlink.h).

Acceptance: native generated IPv4/IPv6/default/extended-table/ECMP/via/terminal
fixtures, malformed/count/interface-reference refusals and unknown-semantics preservation,
order/lifetime stability versus semantic drift; actual unprivileged namespace
route collection; bounded wire fuzz; existing ARMv5 same-boot kernel assertion
and two-boot overlay. No host/guest route write or additional QEMU stage.

Local evidence (2026-10-03): Windows full API/UI/vet/ARMv5 cross-compilation,
pinned Linux Go 1.26.6 whole API tagged vet/race, 5,000 route mutations,
bounded 1,000-execution wire and route fuzz campaigns, 20 feedback contracts,
actual same-boot ARMv5 configured-route observation and clean two-boot overlay
pass. Native actual UID1000/zero-capability collection/recheck has stable FD
counts. Guest self-test runs as root; no non-root ARM privilege claim. Overlay
reuses the verified kernel/packages/probe, not a new full image or clean build.

## Input and authority

Linux-only fixed collector uses bounded RTM_GETLINK/RTM_GETADDR/RTM_GETROUTE dumps
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
multipart completion/status and refusal of interrupted/truncated/undeclared
filtered dumps. The only declared filtering is configured-route scope above.
The standard Go net.Interfaces path does not surface dump-interruption flags or
address state; it cannot establish this contract. The bounded parser is private
and uses native-endian checked lengths, never unsafe casts.

Take two normalized link/address/configured-route sets with namespace checks between/after; require
exact equality independent of order. No retry hides changing or incomplete
observations. Kernel errors, invalid/truncated shape, namespace drift, cancellation
or uncertain close produce no observation and a constant redacted error.
Namespace/socket descriptors are operation-owned; release is attempted once on
every exit path. An uncertain close refuses the observation, without retrying
the descriptor number or claiming confirmed release.

The result is immutable private point-in-time evidence. Recheck collects anew
and refuses a different namespace/interface/address/configured-route set; it does not reset or
manage an Owner's review state. Missing/forged/copied observations are refused.
Caller must separately own any sticky review and transaction lifecycle.

Two matching samples are NOT an atomic netlink transaction, event subscription,
interface generation lease or proof against remove/re-add/ABA. Ifindex, name and
current MAC are transient. Standard address dumps do not qualify tentative/DAD
states as usability: address flags/scope/point-to-point peers are retained, but
no DAD admission, external address conflict, route selection, DNS or management reachability
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
state/DAD admission, routing rules and referenced nexthop/encapsulation objects,
global-use/conflict policy and freshness authority.
M6.2 persistent trial/confirmation/rollback remains required before applying
network policy. NAS/physical NIC, HDD/NAND and product startup are excluded.
