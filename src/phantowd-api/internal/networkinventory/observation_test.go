// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package networkinventory

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func sample() snapshot {
	return snapshot{links: []link{
		{index: 1, name: "lo", kind: 772, flags: 8, mtu: 65536},
		{index: 2, name: "fixture0", kind: 1, mtu: 1500, mac: "\x02\x00\x00\x00\x00\x01"},
	}, addresses: []ipAddress{
		{index: 1, prefix: netip.MustParsePrefix("127.0.0.1/8"), peer: netip.MustParseAddr("127.0.0.1")},
		{index: 2, prefix: netip.MustParsePrefix("192.0.2.10/16"), peer: netip.MustParseAddr("192.0.2.10")},
		{index: 2, prefix: netip.MustParsePrefix("fe80::10/64"), peer: netip.MustParseAddr("fe80::10"), scope: 253},
	}, routes: []route{}}
}

type fixtureReader struct {
	samples        []snapshot
	namespaces     []namespaceID
	reads, nsReads int
	err            bool
	afterRead      func()
}

func (r *fixtureReader) namespace() (namespaceID, error) {
	i := r.nsReads
	r.nsReads++
	if r.err || i >= len(r.namespaces) {
		return namespaceID{}, errors.New("private namespace detail")
	}
	return r.namespaces[i], nil
}
func (r *fixtureReader) read(context.Context) (snapshot, error) {
	i := r.reads
	r.reads++
	if r.afterRead != nil {
		r.afterRead()
	}
	if r.err || i >= len(r.samples) {
		return snapshot{}, errors.New("private reader detail")
	}
	return r.samples[i], nil
}
func readerFixture() *fixtureReader {
	return &fixtureReader{samples: []snapshot{sample(), sample()}, namespaces: []namespaceID{{1, 2}, {1, 2}, {1, 2}}}
}

func TestCompleteObservationIsPrivateImmutableAndOrderIndependent(t *testing.T) {
	r := readerFixture()
	slices.Reverse(r.samples[1].links)
	slices.Reverse(r.samples[1].addresses)
	o, err := observe(context.Background(), r)
	if err != nil || r.reads != 2 || r.nsReads != 3 {
		t.Fatal("complete capture failed")
	}
	summary, err := o.Summary()
	if err != nil || summary != (Summary{Interfaces: 2, Addresses: 3}) {
		t.Fatal("wrong redacted counts")
	}
	r.samples[0].links[0].name = "changed"
	r.samples[0].addresses[0].flags = 64
	if o.state.links[0].name != "lo" || o.state.addresses[0].flags != 0 {
		t.Fatal("observation aliases provider")
	}
	if _, err := json.Marshal(o); err == nil {
		t.Fatal("serialized private observation")
	}
	if _, err := json.Marshal(*o); err == nil {
		t.Fatal("serialized private observation value")
	}
	if err := json.Unmarshal([]byte(`{}`), o); err != ErrUnavailable {
		t.Fatal("accepted forged JSON")
	}
	copy := *o
	for _, invalid := range []*Observation{nil, {}, &copy} {
		if _, err := invalid.Summary(); err != ErrUnavailable {
			t.Fatal("forged summary")
		}
		if err := Recheck(context.Background(), invalid); err != ErrUnavailable {
			t.Fatal("forged recheck")
		}
	}
}

func TestNormalizationRefusesIncompleteMalformedSets(t *testing.T) {
	cases := map[string]func(*snapshot){
		"empty":                         func(s *snapshot) { s.links = nil },
		"too many links":                func(s *snapshot) { s.links = make([]link, MaxInterfaces+1) },
		"missing addresses":             func(s *snapshot) { s.addresses = nil },
		"too many addresses":            func(s *snapshot) { s.addresses = make([]ipAddress, MaxAddresses+1) },
		"zero index":                    func(s *snapshot) { s.links[0].index = 0 },
		"negative index":                func(s *snapshot) { s.links[0].index = 0xffffffff },
		"duplicate index":               func(s *snapshot) { s.links[1].index = 1 },
		"duplicate name":                func(s *snapshot) { s.links[1].name = "lo" },
		"oversize name":                 func(s *snapshot) { s.links[1].name = strings.Repeat("a", 16) },
		"path name":                     func(s *snapshot) { s.links[1].name = "../device" },
		"control name":                  func(s *snapshot) { s.links[1].name = "bad\x00" },
		"oversize MAC":                  func(s *snapshot) { s.links[1].mac = strings.Repeat("x", 33) },
		"missing address interface":     func(s *snapshot) { s.addresses[0].index = 99 },
		"invalid prefix":                func(s *snapshot) { s.addresses[0].prefix = netip.Prefix{} },
		"invalid peer":                  func(s *snapshot) { s.addresses[0].peer = netip.Addr{} },
		"wrong peer family":             func(s *snapshot) { s.addresses[0].peer = netip.MustParseAddr("::1") },
		"zoned peer":                    func(s *snapshot) { s.addresses[2].peer = s.addresses[2].peer.WithZone("fixture0") },
		"duplicate address":             func(s *snapshot) { s.addresses = append(s.addresses, s.addresses[0]) },
		"same identity different flags": func(s *snapshot) { a := s.addresses[0]; a.flags = 1; s.addresses = append(s.addresses, a) },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			s := sample()
			change(&s)
			if normalize(&s) != ErrUnavailable {
				t.Fatal("accepted incomplete set")
			}
		})
	}
	s := sample()
	s.addresses = []ipAddress{}
	if normalize(&s) != nil {
		t.Fatal("valid empty address inventory refused")
	}
}

func TestObservationRefusesDriftWithoutRetry(t *testing.T) {
	cases := map[string]func(*fixtureReader){
		"namespace":             func(r *fixtureReader) { r.namespaces[1].inode++ },
		"last namespace":        func(r *fixtureReader) { r.namespaces[2].inode++ },
		"invalid namespace":     func(r *fixtureReader) { r.namespaces[0].inode = 0 },
		"reader error":          func(r *fixtureReader) { r.samples = r.samples[:1] },
		"namespace error":       func(r *fixtureReader) { r.namespaces = r.namespaces[:1] },
		"changed name":          func(r *fixtureReader) { r.samples[1].links[1].name = "renamed" },
		"changed MAC":           func(r *fixtureReader) { r.samples[1].links[1].mac = "\x02\x00\x00\x00\x00\x02" },
		"changed flags":         func(r *fixtureReader) { r.samples[1].links[1].flags = 1 },
		"changed MTU":           func(r *fixtureReader) { r.samples[1].links[1].mtu = 9000 },
		"changed address state": func(r *fixtureReader) { r.samples[1].addresses[0].flags = 64 },
		"missing link":          func(r *fixtureReader) { r.samples[1].links = r.samples[1].links[:1] },
		"missing address":       func(r *fixtureReader) { r.samples[1].addresses = r.samples[1].addresses[:1] },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			r := readerFixture()
			change(r)
			o, e := observe(context.Background(), r)
			if o != nil || e != ErrUnavailable || r.reads > 2 {
				t.Fatal("drift retry/partial/leak")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := readerFixture()
	r.afterRead = cancel
	if o, e := observe(ctx, r); o != nil || e != ErrUnavailable || r.reads != 1 {
		t.Fatal("cancellation ignored")
	}
	for _, ctx := range []context.Context{nil, ctx} {
		if _, e := observe(ctx, readerFixture()); e != ErrUnavailable {
			t.Fatal("invalid context admitted")
		}
	}
	if _, e := observe(context.Background(), nil); e != ErrUnavailable {
		t.Fatal("nil reader admitted")
	}
	if !reflect.DeepEqual(Observation{}.state, snapshot{}) {
		t.Fatal("unexpected initialized state")
	}
}
