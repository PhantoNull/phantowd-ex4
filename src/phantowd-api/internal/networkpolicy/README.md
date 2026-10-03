<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors -->

# Desired network policy — M6.1a task contract

This internal, platform-independent package validates untrusted schema-1 desired
configuration. It has no sockets, device handles, subprocesses, privileged calls,
persistence, HTTP endpoint or apply operation. A positive revision is syntax,
not a compare-and-swap, confirmed trial or authority to change networking.

## Input and authority

The document contains a hostname, exactly two logical slots (`lan-1`, `lan-2`),
IPv4/IPv6 policies, bounded static routes and DNS. Slots are NOT Linux interface
names, factory MAC identities or a qualified mapping to EX4 sockets. Future
board admission must bind them independently; user input cannot name a device.

IPv4 modes are `disabled`, `dhcp`, `static`; IPv6 modes are `disabled`, `auto`,
`static`. `auto` expresses desired automatic IPv6 addressing, not a qualified
RA/DHCPv6 implementation. At least one family on one slot must be enabled.
Disabled/dynamic families cannot carry static addresses. Static aliases are
limited to four per family. Addresses must be canonical unzoned, unmapped
unicast literals; static IPv4 excludes 0/8, link-local and reserved 240/4.
IPv4 network/broadcast hosts are rejected for prefixes /1–/30; /31 endpoints
are allowed, /32 is allowed without a default gateway. IPv6 static addresses
are global/ULA, not manually configured link-local addresses. No /24 assumption.

A default route is opt-in, with metric 1–65535. Static default gateways must
be on-link and not any local address; IPv6 link-local gateways are allowed
because their logical slot supplies scope. Dynamic defaults have no manual
gateway. Non-default routes require a static family and a canonical, masked,
unicast destination with an on-link gateway and bounded metric. Equal default
metrics per family and equal destination/metric route ties are refused.

Manual DNS has 1–3 canonical unicast servers (including loopback for a separately
managed local resolver); automatic DNS names one slot with
a dynamic family. Empty arrays are explicit. Optional search domains are bounded
ASCII lowercase DNS names. Neither resolver reachability nor the correctness of
leased DNS is established here. No kernel zone, shell text or hostname lookup
is accepted as an address.

## State and failure

Validation has no transitions or owned resources. It does not normalize input,
resolve DNS or mutate the document. Decode returns a zero policy on failure and
a constant redacted error. The shared strict JSON envelope rejects duplicates,
unknown/miscased keys, nulls, invalid UTF-8/surrogates, excessive size/nesting,
wrong field types and trailing documents. Missing semantic fields fail closed;
omitted optional boolean defaults remain false (never implicit route enable).

Known duplicate addresses and overlapping configured static subnets across slots
are refused; aliases within one slot are allowed. This is conservative desired
policy, NOT a duplicate-address detection protocol, global-use census or proof
that DHCP/RA addresses will not conflict. Runtime interface identity, routes,
address conflicts and management reachability must be separately observed.

## Change boundary and acceptance

Reuse `internal/configjson`; do not add another network owner or address parser.
Tests cover dual-stack DHCP/static/disabled modes, /16,/31,/32 and IPv6 scope,
routes/default priorities, DNS, aliases/conflicts, strict JSON and input bounds.
Add a fixed-count malformed-input property test and a same-boot ARMv5 QEMU
self-test with explicit positive/negative assertions, no network syscall.

Non-goals: persistent state, real interface binding, DHCP/RA client behavior,
route application, bridge/bond/failover, firewall, time/discovery, SSH, trial
confirmation/rollback or HTTP UI. M6.1 runtime admission and M6.2 recoverable
application remain prerequisites to exposing any network mutation. NAS/HDD/NAND
and physical two-port qualification remain excluded.
