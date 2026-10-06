// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package networkinventory privately observes kernel network state. It grants
// no configuration authority, stable hardware identity or interface lease.
package networkinventory

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
)

const MaxInterfaces = 64
const MaxAddresses = 256
const MaxRoutes = 512
const MaxRules = 256
const MaxNextHopObjects = 128
const maxNextHops = 32

var ErrUnavailable = errors.New("network observation unavailable")
var ErrChanged = errors.New("network observation changed")

type namespaceID struct{ device, inode uint64 }
type link struct {
	index                     uint32
	name                      string
	kind                      uint16
	flags, mtu, master, lower uint32
	mac                       string // Owned byte string, not factory identity.
}
type ipAddress struct {
	index  uint32
	prefix netip.Prefix
	peer   netip.Addr
	flags  uint32
	scope  uint8
}
type snapshot struct {
	links     []link
	addresses []ipAddress
	routes    []route
	rules     []rule
	objects   []nextHopObject
}

type nextHopMember struct {
	id, weight uint32
}

type nextHopObject struct {
	id, output, flags       uint32
	family, scope, protocol uint8
	gateway                 netip.Addr
	groupType               uint16
	blackhole, fdb          bool
	members                 []nextHopMember
	semantic                [32]byte
	unresolved              bool
}

type rule struct {
	family, action, tos            uint8
	destination, source            netip.Prefix
	table, priority, target, flags uint32
	input, output                  string
	semantic                       [32]byte
	unresolved                     bool
}

// Digests retain bounded, canonical wire semantics privately. They are equality
// evidence only, not authenticated identity, reachability or route authority.
type route struct {
	destination, source                 netip.Prefix
	table, metric, input, output, flags uint32
	protocol, scope, kind, tos          uint8
	gateway, preferred, via             netip.Addr
	next                                []nextHop
	semantic                            [32]byte
	unresolved                          bool
	objectID                            uint32
}
type nextHop struct {
	index        uint32
	flags, hops  uint8
	gateway, via netip.Addr
	semantic     [32]byte
	unresolved   bool
}

// Observation is immutable; no raw namespace IDs, names, MACs or addresses leave
// this boundary. It is point-in-time evidence, not a serializable capability.
type Observation struct {
	self      *Observation
	namespace namespaceID
	state     snapshot
}

type Summary struct {
	Interfaces               int
	Addresses                int
	Routes                   int
	UnresolvedRoutes         int
	Rules                    int
	UnresolvedRules          int
	NextHopObjects           int
	UnresolvedNextHopObjects int
}

func (o *Observation) Summary() (Summary, error) {
	if o == nil || o.self != o {
		return Summary{}, ErrUnavailable
	}
	unresolved := 0
	for _, r := range o.state.routes {
		if r.unresolved {
			unresolved++
		}
	}
	unresolvedRules := 0
	for _, r := range o.state.rules {
		if r.unresolved {
			unresolvedRules++
		}
	}
	unresolvedObjects := 0
	for _, n := range o.state.objects {
		if n.unresolved {
			unresolvedObjects++
		}
	}
	return Summary{Interfaces: len(o.state.links), Addresses: len(o.state.addresses), Routes: len(o.state.routes), UnresolvedRoutes: unresolved, Rules: len(o.state.rules), UnresolvedRules: unresolvedRules, NextHopObjects: len(o.state.objects), UnresolvedNextHopObjects: unresolvedObjects}, nil
}
func (Observation) MarshalJSON() ([]byte, error) { return nil, ErrUnavailable }
func (*Observation) UnmarshalJSON([]byte) error  { return ErrUnavailable }

type reader interface {
	namespace() (namespaceID, error)
	read(context.Context) (snapshot, error)
}

func observe(ctx context.Context, r reader) (*Observation, error) {
	if ctx == nil || ctx.Err() != nil || r == nil {
		return nil, ErrUnavailable
	}
	ns, err := r.namespace()
	if err != nil || ns.inode == 0 {
		return nil, ErrUnavailable
	}
	first, err := r.read(ctx)
	if err != nil || normalize(&first) != nil || ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	middle, err := r.namespace()
	if err != nil || middle != ns {
		return nil, ErrUnavailable
	}
	second, err := r.read(ctx)
	if err != nil || normalize(&second) != nil || ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	last, err := r.namespace()
	if err != nil || last != ns || !equal(first, second) || ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	o := &Observation{namespace: ns, state: first}
	o.self = o
	return o, nil
}

func normalize(s *snapshot) error {
	if len(s.links) == 0 || len(s.links) > MaxInterfaces || s.addresses == nil || len(s.addresses) > MaxAddresses || s.routes == nil || len(s.routes) > MaxRoutes || s.rules == nil || len(s.rules) > MaxRules || s.objects == nil || len(s.objects) > MaxNextHopObjects {
		return ErrUnavailable
	}
	// Clone provider-owned data so a result does not alias an injected reader.
	s.links = slices.Clone(s.links)
	s.addresses = slices.Clone(s.addresses)
	s.routes = slices.Clone(s.routes)
	s.rules = slices.Clone(s.rules)
	s.objects = slices.Clone(s.objects)
	slices.SortFunc(s.links, func(a, b link) int {
		if a.index < b.index {
			return -1
		}
		if a.index > b.index {
			return 1
		}
		return 0
	})
	for i, l := range s.links {
		if l.index == 0 || l.index > 0x7fffffff || !kernelName(l.name) || len(l.mac) > 32 ||
			(i > 0 && s.links[i-1].index == l.index) {
			return ErrUnavailable
		}
		for _, old := range s.links[:i] {
			if old.name == l.name {
				return ErrUnavailable
			}
		}
	}
	slices.SortFunc(s.addresses, compareAddress)
	for i, a := range s.addresses {
		if !a.prefix.IsValid() || !a.peer.IsValid() || a.prefix.Addr().BitLen() != a.peer.BitLen() || a.prefix.Addr().Zone() != "" || a.peer.Zone() != "" ||
			(i > 0 && sameAddressIdentity(s.addresses[i-1], a)) {
			return ErrUnavailable
		}
		found := false
		for _, l := range s.links {
			found = found || l.index == a.index
		}
		if !found {
			return ErrUnavailable
		}
	}
	if normalizeObjects(s) != nil {
		return ErrUnavailable
	}
	for i := range s.routes {
		r := &s.routes[i]
		if !r.destination.IsValid() || !r.source.IsValid() || r.destination != r.destination.Masked() || r.source != r.source.Masked() || r.destination.Addr().BitLen() != r.source.Addr().BitLen() || len(r.next) > maxNextHops {
			return ErrUnavailable
		}
		r.next = slices.Clone(r.next)
		if r.objectID != 0 && findObject(s.objects, r.objectID) == nil {
			return ErrUnavailable
		}
		if r.objectID != 0 {
			r.unresolved = true
		}
		for _, index := range []uint32{r.input, r.output} {
			if index != 0 && !hasInterface(s.links, index) {
				return ErrUnavailable
			}
		}
		for _, n := range r.next {
			if !hasInterface(s.links, n.index) {
				return ErrUnavailable
			}
		}
	}
	slices.SortFunc(s.routes, func(a, b route) int { return bytes.Compare(a.semantic[:], b.semantic[:]) })
	for i := 1; i < len(s.routes); i++ {
		if s.routes[i-1].semantic == s.routes[i].semantic {
			return ErrUnavailable
		}
	}
	// Family dump order is irrelevant. Within a family, equal-priority ordering
	// and even duplicate multiplicity affect kernel policy; never digest-sort it.
	slices.SortStableFunc(s.rules, func(a, b rule) int { return int(a.family) - int(b.family) })
	for i := range s.rules {
		r := &s.rules[i]
		if !r.destination.IsValid() || !r.source.IsValid() || r.destination != r.destination.Masked() || r.source != r.source.Masked() || r.source.Addr().BitLen() != r.destination.Addr().BitLen() {
			return ErrUnavailable
		}
		if i > 0 && s.rules[i-1].family == r.family && s.rules[i-1].priority > r.priority {
			return ErrUnavailable
		}
		for _, ref := range []struct {
			name     string
			detached uint32
		}{{r.input, 8}, {r.output, 16}} {
			if ref.name == "" {
				continue
			}
			found := false
			for _, l := range s.links {
				found = found || l.name == ref.name
			}
			if !found {
				if r.flags&ref.detached == 0 {
					return ErrUnavailable
				}
				r.unresolved = true
			}
		}
	}
	return nil
}

func hasInterface(links []link, index uint32) bool {
	for _, l := range links {
		if l.index == index {
			return true
		}
	}
	return false
}

func kernelName(v string) bool {
	if len(v) == 0 || len(v) > 15 || v == "." || v == ".." {
		return false
	}
	for _, c := range v {
		if c <= ' ' || c > '~' || strings.ContainsRune("/:\\", c) {
			return false
		}
	}
	return true
}

func compareAddress(a, b ipAddress) int {
	if a.index < b.index {
		return -1
	}
	if a.index > b.index {
		return 1
	}
	if c := a.prefix.Addr().Compare(b.prefix.Addr()); c != 0 {
		return c
	}
	if a.prefix.Bits() < b.prefix.Bits() {
		return -1
	}
	if a.prefix.Bits() > b.prefix.Bits() {
		return 1
	}
	return a.peer.Compare(b.peer)
}
func sameAddressIdentity(a, b ipAddress) bool { return compareAddress(a, b) == 0 }
func equal(a, b snapshot) bool {
	return slices.Equal(a.links, b.links) && slices.Equal(a.addresses, b.addresses) && slices.Equal(a.rules, b.rules) && slices.EqualFunc(a.objects, b.objects, func(a, b nextHopObject) bool {
		return a.id == b.id && a.output == b.output && a.flags == b.flags && a.family == b.family && a.scope == b.scope && a.protocol == b.protocol && a.gateway == b.gateway && a.groupType == b.groupType && a.blackhole == b.blackhole && a.fdb == b.fdb && a.semantic == b.semantic && a.unresolved == b.unresolved && slices.Equal(a.members, b.members)
	}) && slices.EqualFunc(a.routes, b.routes, func(a, b route) bool {
		return a.destination == b.destination && a.source == b.source && a.table == b.table && a.metric == b.metric && a.input == b.input && a.output == b.output && a.flags == b.flags && a.protocol == b.protocol && a.scope == b.scope && a.kind == b.kind && a.tos == b.tos && a.gateway == b.gateway && a.preferred == b.preferred && a.via == b.via && a.semantic == b.semantic && a.unresolved == b.unresolved && a.objectID == b.objectID && slices.Equal(a.next, b.next)
	})
}

func findObject(objects []nextHopObject, id uint32) *nextHopObject {
	for i := range objects {
		if objects[i].id == id {
			return &objects[i]
		}
	}
	return nil
}

func normalizeObjects(s *snapshot) error {
	slices.SortFunc(s.objects, func(a, b nextHopObject) int {
		if a.id < b.id {
			return -1
		}
		if a.id > b.id {
			return 1
		}
		return 0
	})
	for i := range s.objects {
		n := &s.objects[i]
		if n.id == 0 || i > 0 && s.objects[i-1].id == n.id || len(n.members) > maxNextHops || n.output != 0 && !hasInterface(s.links, n.output) {
			return ErrUnavailable
		}
		n.members = slices.Clone(n.members)
		for j, m := range n.members {
			target := findObject(s.objects, m.id)
			if target == nil || len(target.members) != 0 || m.id == n.id || m.weight == 0 || m.weight > 65535 || target.fdb != n.fdb || target.blackhole && len(n.members) > 1 {
				return ErrUnavailable
			}
			for _, previous := range n.members[:j] {
				if previous.id == m.id {
					return ErrUnavailable
				}
			}
		}
	}
	// No nested groups: a second pass propagates unresolved leaf semantics
	// independent of object dump order. It never makes a route usable.
	for i := range s.objects {
		n := &s.objects[i]
		for _, m := range n.members {
			n.unresolved = n.unresolved || findObject(s.objects, m.id).unresolved
		}
	}
	return nil
}

// Recheck is another observation, not an Owner recovery or sticky-state reset.
func Recheck(ctx context.Context, prior *Observation) error {
	if prior == nil || prior.self != prior {
		return ErrUnavailable
	}
	current, err := Collect(ctx)
	if err != nil {
		return ErrUnavailable
	}
	if current.namespace != prior.namespace || !equal(current.state, prior.state) {
		return ErrChanged
	}
	return nil
}
