// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package networkinventory

import (
	"context"
	"encoding/json"
	"math/rand/v2"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/networkpolicy"
)

func addressPolicy() networkpolicy.Policy {
	disabled := networkpolicy.Family{Mode: "disabled", Addresses: []string{}}
	return networkpolicy.Policy{Format: networkpolicy.Format, SchemaVersion: 1, Revision: 1, Hostname: "preflight-test",
		Interfaces: []networkpolicy.Interface{
			{Slot: "lan-1", IPv4: networkpolicy.Family{Mode: "static", Addresses: []string{"192.0.2.10/16"}},
				IPv6: networkpolicy.Family{Mode: "static", Addresses: []string{"2001:db8:1::10/64"}}},
			{Slot: "lan-2", IPv4: disabled, IPv6: disabled},
		}, Routes: []networkpolicy.Route{}, DNS: networkpolicy.DNS{Mode: "manual", Servers: []string{"192.0.2.53"}, SearchDomains: []string{}}}
}

func addressSnapshot() snapshot {
	s := sample()
	s.links[1].flags = 1 | 0x10000
	s.links = append(s.links, link{index: 3, name: "foreign0", kind: 1, flags: 1 | 0x10000, mtu: 1500, mac: "\x02\x00\x00\x00\x00\x02"})
	s.addresses = append(s.addresses, ipAddress{index: 2, prefix: netip.MustParsePrefix("2001:db8:1::10/64"), peer: netip.MustParseAddr("2001:db8:1::10"), flags: 0x80},
		ipAddress{index: 3, prefix: netip.MustParsePrefix("198.51.100.10/24"), peer: netip.MustParseAddr("198.51.100.10"), flags: 0x80})
	return s
}

func addressObservation(t *testing.T, state snapshot) *Observation {
	t.Helper()
	r := &fixtureReader{samples: []snapshot{state, state}, namespaces: []namespaceID{{1, 2}, {1, 2}, {1, 2}}}
	o, err := observe(context.Background(), r)
	if err != nil {
		t.Fatal("fixture is not a complete valid observation")
	}
	return o
}

func TestAddressPreflightCountersAndFullInventory(t *testing.T) {
	base := localAddressSummary{static: 2, exact: 2}
	cases := []struct {
		name   string
		change func(*snapshot, *networkpolicy.Policy)
		want   localAddressSummary
	}{
		{"exact /16 dual stack", func(*snapshot, *networkpolicy.Policy) {}, base},
		{"missing alias", func(_ *snapshot, p *networkpolicy.Policy) {
			p.Interfaces[0].IPv4.Addresses = append(p.Interfaces[0].IPv4.Addresses, "192.0.2.11/16")
		}, localAddressSummary{static: 3, exact: 2, missing: 1}},
		{"prefix change", func(_ *snapshot, p *networkpolicy.Policy) { p.Interfaces[0].IPv4.Addresses[0] = "192.0.2.10/24" }, localAddressSummary{static: 2, exact: 1, missing: 1}},
		{"elsewhere including disabled/unbound links", func(s *snapshot, _ *networkpolicy.Policy) {
			s.addresses[4].prefix = netip.MustParsePrefix("192.0.2.10/16")
			s.addresses[4].peer = s.addresses[4].prefix.Addr()
		}, localAddressSummary{static: 2, exact: 2, addressElsewhere: 1, overlapElsewhere: 1}},
		{"overlap without duplicate", func(s *snapshot, _ *networkpolicy.Policy) {
			s.addresses[4].prefix = netip.MustParsePrefix("192.0.3.20/24")
			s.addresses[4].peer = s.addresses[4].prefix.Addr()
		}, localAddressSummary{static: 2, exact: 2, overlapElsewhere: 1}},
		{"point to point destination is not local address", func(s *snapshot, _ *networkpolicy.Policy) { s.addresses[4].peer = netip.MustParseAddr("192.0.2.10") }, localAddressSummary{static: 2, exact: 2, peerElsewhere: 1}},
		{"IPv4 alias flags", func(s *snapshot, _ *networkpolicy.Policy) { s.addresses[1].flags = 0x80 | 1 | 0x200 }, base},
		{"IPv6 no-prefix-route remains routing-unqualified", func(s *snapshot, _ *networkpolicy.Policy) { s.addresses[3].flags |= 0x200 }, base},
		{"down link blocks both enabled families", func(s *snapshot, _ *networkpolicy.Policy) { s.links[1].flags = 0 }, localAddressSummary{static: 2, exact: 2, linkFlagsBlocked: 2}},
		{"lower-down link", func(s *snapshot, _ *networkpolicy.Policy) { s.links[1].flags = 1 }, localAddressSummary{static: 2, exact: 2, linkFlagsBlocked: 2}},
		{"dormant link", func(s *snapshot, _ *networkpolicy.Policy) { s.links[1].flags |= 0x20000 }, localAddressSummary{static: 2, exact: 2, linkFlagsBlocked: 2}},
		{"DHCP and auto remain unresolved", func(_ *snapshot, p *networkpolicy.Policy) {
			p.Interfaces[0].IPv4 = networkpolicy.Family{Mode: "dhcp", Addresses: []string{}}
			p.Interfaces[0].IPv6 = networkpolicy.Family{Mode: "auto", Addresses: []string{}}
		}, localAddressSummary{dynamic: 2}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, p := addressSnapshot(), addressPolicy()
			tc.change(&s, &p)
			o := addressObservation(t, s)
			before, _ := json.Marshal(p)
			got, err := assessLocalAddresses(context.Background(), o, p, [2]uint32{2, 3})
			if err != nil || got != tc.want {
				t.Fatalf("counts=%+v want=%+v err=%v", got, tc.want, err)
			}
			after, _ := json.Marshal(p)
			if string(before) != string(after) {
				t.Fatal("helper changed desired policy")
			}
			p.Interfaces[0], p.Interfaces[1] = p.Interfaces[1], p.Interfaces[0]
			if reordered, err := assessLocalAddresses(context.Background(), o, p, [2]uint32{2, 3}); err != nil || reordered != got {
				t.Fatal("policy slot ordering changed assessment")
			}
		})
	}
}

func TestAddressPreflightStateFlagsScopeAndPeer(t *testing.T) {
	for _, flag := range []uint32{2, 4, 8, 16, 32, 64, 0x100, 0x400, 0x800, 0x1000, 1 << 31} {
		for _, pos := range []int{1, 3} {
			s := addressSnapshot()
			s.addresses[pos].flags = 0x80 | flag
			got, err := assessLocalAddresses(context.Background(), addressObservation(t, s), addressPolicy(), [2]uint32{2, 3})
			if err != nil || got != (localAddressSummary{static: 2, exact: 2, addressFlagsBlocked: 1}) {
				t.Fatalf("unqualified flags not counted: flag=%x position=%d", flag, pos)
			}
		}
	}
	for _, change := range []func(*snapshot){
		func(s *snapshot) { s.addresses[3].flags |= 1 },
		func(s *snapshot) { s.addresses[1].scope = 253 },
		func(s *snapshot) { s.addresses[1].peer = netip.MustParseAddr("192.0.2.1") },
	} {
		s := addressSnapshot()
		change(&s)
		got, err := assessLocalAddresses(context.Background(), addressObservation(t, s), addressPolicy(), [2]uint32{2, 3})
		if err != nil || got.addressFlagsBlocked != 1 {
			t.Fatal("unqualified scope/peer/temporary state accepted")
		}
	}
}

func TestAddressPreflightHostPrefixesAndUnboundInterfaceConflicts(t *testing.T) {
	for _, prefix := range []string{"192.0.2.10/31", "192.0.2.10/32"} {
		s, p := addressSnapshot(), addressPolicy()
		p.Interfaces[0].IPv4.Addresses[0] = prefix
		s.addresses[1].prefix = netip.MustParsePrefix(prefix)
		got, err := assessLocalAddresses(context.Background(), addressObservation(t, s), p, [2]uint32{2, 0})
		if err != nil || got != (localAddressSummary{static: 2, exact: 2, unbound: 1}) {
			t.Fatal("valid /31 or /32 observation refused")
		}
	}
	s, p := addressSnapshot(), addressPolicy()
	p.Interfaces[0].IPv6.Addresses[0] = "2001:db8:1::10/128"
	s.addresses[3].prefix = netip.MustParsePrefix(p.Interfaces[0].IPv6.Addresses[0])
	got, err := assessLocalAddresses(context.Background(), addressObservation(t, s), p, [2]uint32{2, 0})
	if err != nil || got != (localAddressSummary{static: 2, exact: 2, unbound: 1}) {
		t.Fatal("valid IPv6 /128 observation refused")
	}
	// This fourth, non-Ethernet interface is neither a bound nor disabled slot.
	s.links = append(s.links, link{index: 4, name: "unbound0", kind: 772})
	s.addresses = append(s.addresses, ipAddress{index: 4, prefix: netip.MustParsePrefix("192.0.2.10/32"), peer: netip.MustParseAddr("192.0.2.10")})
	got, err = assessLocalAddresses(context.Background(), addressObservation(t, s), p, [2]uint32{2, 0})
	if err != nil || got.addressElsewhere != 1 || got.overlapElsewhere != 1 || got.unbound != 1 {
		t.Fatal("unbound interface use silently excluded")
	}
}

func TestAddressPreflightGatewayScopeAndDeduplication(t *testing.T) {
	s, p := addressSnapshot(), addressPolicy()
	p.Interfaces[0].IPv4.DefaultRoute, p.Interfaces[0].IPv4.Metric, p.Interfaces[0].IPv4.Gateway = true, 100, "192.0.2.1"
	p.Interfaces[0].IPv6.DefaultRoute, p.Interfaces[0].IPv6.Metric, p.Interfaces[0].IPv6.Gateway = true, 100, "fe80::1"
	p.Routes = []networkpolicy.Route{{Slot: "lan-1", Destination: "198.51.100.0/24", Gateway: "192.0.2.1", Metric: 200}}
	s.addresses = append(s.addresses,
		ipAddress{index: 3, prefix: netip.MustParsePrefix("192.0.2.1/32"), peer: netip.MustParseAddr("192.0.2.1")},
		ipAddress{index: 3, prefix: netip.MustParsePrefix("fe80::1/64"), peer: netip.MustParseAddr("fe80::1"), scope: 253})
	got, err := assessLocalAddresses(context.Background(), addressObservation(t, s), p, [2]uint32{2, 3})
	if err != nil || got.localGateways != 1 {
		t.Fatal("global local-gateway use or scoped deduplication failed")
	}
	s.addresses = append(s.addresses, ipAddress{index: 2, prefix: netip.MustParsePrefix("fe80::1/64"), peer: netip.MustParseAddr("fe80::1"), scope: 253})
	got, err = assessLocalAddresses(context.Background(), addressObservation(t, s), p, [2]uint32{2, 3})
	if err != nil || got.localGateways != 2 {
		t.Fatal("same-link link-local gateway use not counted")
	}
}

func TestAddressPreflightRefusesInvalidInputWithoutPartialCounts(t *testing.T) {
	o := addressObservation(t, addressSnapshot())
	copy := *o
	for _, bad := range []*Observation{nil, {}, &copy} {
		if got, err := assessLocalAddresses(context.Background(), bad, addressPolicy(), [2]uint32{2, 3}); err != ErrUnavailable || got != (localAddressSummary{}) {
			t.Fatal("forged observation accepted")
		}
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{nil, canceled} {
		if got, err := assessLocalAddresses(ctx, o, addressPolicy(), [2]uint32{2, 3}); err != ErrUnavailable || got != (localAddressSummary{}) {
			t.Fatal("invalid context accepted")
		}
	}
	for _, bindings := range [][2]uint32{{0, 3}, {2, 2}, {1, 3}, {2, 99}, {2, 1}, {99, 0}} {
		if got, err := assessLocalAddresses(context.Background(), o, addressPolicy(), bindings); err != ErrUnavailable || got != (localAddressSummary{}) {
			t.Fatal("invalid or unsupported binding accepted")
		}
	}
	for _, change := range []func(*link){
		func(l *link) { l.kind = 772 }, func(l *link) { l.flags |= 8 },
		func(l *link) { l.master = 1 }, func(l *link) { l.lower = 1 },
		func(l *link) { l.mac = "" }, func(l *link) { l.mac = "\x01\x00\x00\x00\x00\x01" },
		func(l *link) { l.mac = "\x00\x00\x00\x00\x00\x00" },
	} {
		s := addressSnapshot()
		change(&s.links[2]) // Refuse even a disabled bound slot, without partial success.
		if got, err := assessLocalAddresses(context.Background(), addressObservation(t, s), addressPolicy(), [2]uint32{2, 3}); err != ErrUnavailable || got != (localAddressSummary{}) {
			t.Fatal("unsupported link shape returned partial counts")
		}
	}
	p := addressPolicy()
	p.Revision = 0
	if got, err := assessLocalAddresses(context.Background(), o, p, [2]uint32{2, 3}); err != ErrUnavailable || got != (localAddressSummary{}) {
		t.Fatal("invalid desired policy accepted")
	}
	got, err := assessLocalAddresses(context.Background(), o, addressPolicy(), [2]uint32{2, 0})
	if err != nil || got != (localAddressSummary{static: 2, exact: 2, unbound: 1}) {
		t.Fatal("explicit disabled unbound slot refused")
	}
}

func TestAddressPreflightBoundedMutationOrderPrivacyAndConcurrency(t *testing.T) {
	rng := rand.New(rand.NewPCG(0x61646472, 0x70726566))
	for i := 0; i < 2000; i++ {
		s := addressSnapshot()
		s.addresses[4].flags = rng.Uint32()
		s.addresses[4].prefix = netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 0, byte(rng.Uint32()), byte(rng.Uint32())}), 24)
		s.addresses[4].peer = s.addresses[4].prefix.Addr()
		if i%2 == 0 {
			s.addresses[1].flags = rng.Uint32()
		}
		o := addressObservation(t, s)
		got, err := assessLocalAddresses(context.Background(), o, addressPolicy(), [2]uint32{2, 0})
		if err != nil || got.static != 2 || got.exact+got.missing != got.static || got.addressElsewhere > 1 || got.overlapElsewhere > 1 || got.addressFlagsBlocked > 1 || got.unbound != 1 {
			t.Fatal("bounded mutation lost conservative counters")
		}
		slices.Reverse(s.links)
		slices.Reverse(s.addresses)
		ordered, err := assessLocalAddresses(context.Background(), addressObservation(t, s), addressPolicy(), [2]uint32{2, 0})
		if err != nil || !reflect.DeepEqual(ordered, got) {
			t.Fatal("observation ordering affected counts")
		}
	}
	o := addressObservation(t, addressSnapshot())
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := assessLocalAddresses(context.Background(), o, addressPolicy(), [2]uint32{2, 3})
			data, _ := json.Marshal(got)
			if err != nil || got.exact != 2 || strings.Contains(string(data), "192.0.2") {
				t.Error("immutable observation assessment failed or leaked")
			}
		}()
	}
	wg.Wait()
}
