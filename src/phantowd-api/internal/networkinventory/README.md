<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors -->

# Private kernel network observation — M6.1b/M6.1c task contract

## M6.1e nexthop-object task contract (implementation pending)

Extend the existing private collector with one fixed strict GETNEXTHOP
AF_UNSPEC dump per sample: zeroed eight-byte nhmsg, no selectors, statistics,
hardware callbacks, mutation, subprocess or additional privilege. Require the
complete returned roster, including unreferenced objects and an explicitly
completed empty set. Missing support or malformed/interrupted/filtered dumps
refuse the entire observation; no fallback to route-only success.

Bound objects to 128 and ordered group members to 32, within the existing byte
and total socket-time budgets. Retain IDs, family/protocol/scope/flags, local
output interface, gateway, blackhole/FDB, group type and effective 16-bit
weights privately. Object dump and attribute order are irrelevant; group
member order is meaningful. Duplicate IDs/members, missing route/group targets,
group nesting and missing local interfaces refuse the complete result. Clone
member slices and compare the complete roster across both samples/rechecks.

Validate pinned Linux 6.18.54 response framing, including the group response
OP_FLAGS bit and weight_high. Resilient groups remain unresolved without bucket
observations; validate/canonicalize their nested configuration while excluding
only the elapsed unbalanced-time counter. FDB, encapsulation and unknown
semantics remain unresolved. Referenced route IDs remain unresolved: joining
an object is not route evaluation or permission to apply network policy.
Only aggregate object/unresolved counts leave this boundary; JSON refusal and
all existing ownership/namespace protections remain unchanged.

Acceptance: fixed request/wire completion and failure fixtures; IPv4/IPv6,
blackhole/FDB, ordered/weighted groups, resilient nested framing and volatile
counter tests; missing/duplicate/reference/count/drift/alias/privacy refusals;
bounded mutation/fuzz; actual zero-capability native collection and descriptor
counts; Windows preflight and same-boot ARMv5 collection plus two-boot overlay
using the verified existing kernel. No NAS, physical NIC, disk, NAND, HTTP,
product startup, route selection or network application is authorized.

ABI references: [nexthop UAPI](https://github.com/gregkh/linux/blob/v6.18.54/include/uapi/linux/nexthop.h)
and [dump implementation](https://github.com/gregkh/linux/blob/v6.18.54/net/ipv4/nexthop.c).
The pinned IPv4 Makefile builds nexthop.o with INET; no new kernel option is
proposed. Actual guest collection must prove support, not source inspection.

The same ordered-semantics boundary includes correcting inline RTA_MULTIPATH:
do not sort its members before comparing observations. Pinned fib_rebalance
assigns cumulative hash ranges in member order. Acceptance requires a failing
real-parser regression for reordered members, observed-set drift refusal and
continued attribute-order stability; preserve non-adjacent duplicate refusal.
This supersedes the earlier M6.1c member-order normalization claim, not its
immutable dated evidence. No route write or evaluator is introduced.

## M6.1d routing-rule task contract

Extend the same fixed socket/namespace boundary with two strict GETRULE requests,
fixed AF_INET and AF_INET6; no caller/table/interface selectors or mutation.
Require complete IPv4/IPv6 rule observations in each
sample; missing subsystem, filtered/interrupted/truncated/error replies refuse
the whole observation. Keep family/header, source/destination, priority/table,
action/flags, interface names, marks, UID/port ranges, suppressors and unknown
attributes private. Check framing/scalar/range/name shape; unresolved/detached
references and unknown semantics remain explicitly unresolved, not usable policy.

Bound rule count to 256 and retain the existing byte/time budget. Attribute order
is irrelevant, but kernel rule order within each family (especially equal
priorities) is meaningful: preserve order and duplicate multiplicity. Only
cross-family dump ordering is normalized. Two samples must match. Summary adds
rule and unresolved counts only, no paths/IDs/selectors or HTTP. Rule observation
is not policy evaluation, route/object resolution, reachability or freshness.

The generic AF_UNSPEC proposal was corrected after native diagnosis reproduced
an extra family128 in the same dump. The collector does NOT silently skip such
records: it now emits exactly the two IP-family requests and validates the
response family. A RED/GREEN request-shape regression proves the family is
actually in the packet. Unknown families/requests and arbitrary selectors are
not accepted. See the [pinned rule UAPI](https://github.com/gregkh/linux/blob/v6.18.54/include/uapi/linux/fib_rules.h)
and [dump/order implementation](https://github.com/gregkh/linux/blob/v6.18.54/net/core/fib_rules.c).

The preceding QEMU kernel lacked FIB_RULES/multiple-table support. Enable only
that network capability in its existing networked-storage fragment, audit the
resolved kernel configuration and refresh Linux in the SAME cached workspace.
No new Buildroot configuration namespace, image/volume or physical profile.
Old-kernel fast overlays cannot qualify this change. Acceptance requires native
actual rule collection and malformed/order/drift/privacy/fuzz tests, Windows
preflight, then complete cached Buildroot/ARMv5 qualification with a positive
actual rule count in the existing mandatory same-boot assertion and two-boot.

Local evidence (2026-10-03): final native vet/race and actual UID1000,
zero-capability collection/recheck with stable descriptor counts pass, including
bounded rule mutation/fuzz, fixed request shape, order/multiplicity, drift and
privacy refusals. Windows full preflight and ARMv5 cross-compilation pass.
Complete cached integration on unchanged `e0986fc` (tree `f86d6e3`) refreshes
the actual kernel and passes whole Linux host/vet/race/fixed-fuzz, image/legal/
SBOM, standard/MD/two-boot and every launcher/Owner/loader/atomic/Samba/SMART
guest lane. The mandatory actual guest observation requires positive rule counts;
resolved multiple-table/FIB_RULES options, seven exported hashes and exact
image/export/target API equality were checked independently. Guest self-test is
root; this is not non-root ARM, independent clean build, physical EX4 or product
qualification. No rule application or evaluator is installed.

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
