// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package networkinventory privately observes kernel network state. It grants
// no configuration authority, stable hardware identity or interface lease.
package networkinventory

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
)

const MaxInterfaces = 64
const MaxAddresses = 256

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
}

// Observation is immutable; no raw namespace IDs, names, MACs or addresses leave
// this boundary. It is point-in-time evidence, not a serializable capability.
type Observation struct {
	self      *Observation
	namespace namespaceID
	state     snapshot
}

type Summary struct {
	Interfaces int
	Addresses  int
}

func (o *Observation) Summary() (Summary, error) {
	if o == nil || o.self != o {
		return Summary{}, ErrUnavailable
	}
	return Summary{len(o.state.links), len(o.state.addresses)}, nil
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
	if len(s.links) == 0 || len(s.links) > MaxInterfaces || s.addresses == nil || len(s.addresses) > MaxAddresses {
		return ErrUnavailable
	}
	// Clone provider-owned data so a result does not alias an injected reader.
	s.links = slices.Clone(s.links)
	s.addresses = slices.Clone(s.addresses)
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
	return nil
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
	return slices.Equal(a.links, b.links) && slices.Equal(a.addresses, b.addresses)
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
