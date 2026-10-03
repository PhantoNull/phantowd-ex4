//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package networkinventory

import (
	"context"
	"net/netip"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/networkpolicy"
)

// QEMUAddressFixture uses generated observations, not real interface bindings
// or an external conflict probe. Actual kernel collection is checked separately.
func QEMUAddressFixture() error {
	disabled := networkpolicy.Family{Mode: "disabled", Addresses: []string{}}
	p := networkpolicy.Policy{Format: networkpolicy.Format, SchemaVersion: 1, Revision: 1, Hostname: "preflight-fixture",
		Interfaces: []networkpolicy.Interface{
			{Slot: "lan-1", IPv4: networkpolicy.Family{Mode: "static", Addresses: []string{"192.0.2.10/16"}}, IPv6: disabled},
			{Slot: "lan-2", IPv4: disabled, IPv6: disabled},
		}, Routes: []networkpolicy.Route{}, DNS: networkpolicy.DNS{Mode: "manual", Servers: []string{"192.0.2.53"}, SearchDomains: []string{}}}
	state := snapshot{
		links: []link{{index: 2, name: "generated0", kind: 1, flags: 1 | 0x10000, mac: "\x02\x00\x00\x00\x00\x01"},
			{index: 3, name: "outside0", kind: 772}},
		addresses: []ipAddress{{index: 2, prefix: netip.MustParsePrefix("192.0.2.10/16"), peer: netip.MustParseAddr("192.0.2.10"), flags: 0x80}},
		routes:    []route{}, rules: []rule{}, objects: []nextHopObject{},
	}
	if normalize(&state) != nil {
		return ErrUnavailable
	}
	// Fixed qemu-tagged generated input only; not a product observation provider.
	o := &Observation{namespace: namespaceID{1, 1}, state: state}
	o.self = o
	got, err := assessLocalAddresses(context.Background(), o, p, [2]uint32{2, 0})
	if err != nil || got != (localAddressSummary{static: 1, exact: 1, unbound: 1}) {
		return ErrUnavailable
	}
	state.addresses = append(state.addresses, ipAddress{index: 3, prefix: netip.MustParsePrefix("192.0.2.10/32"), peer: netip.MustParseAddr("192.0.2.10")})
	if normalize(&state) != nil {
		return ErrUnavailable
	}
	o.state = state
	got, err = assessLocalAddresses(context.Background(), o, p, [2]uint32{2, 0})
	if err != nil || got.addressElsewhere != 1 || got.overlapElsewhere != 1 {
		return ErrUnavailable
	}
	state.addresses[0].flags |= 64 // TENTATIVE must be flagged, not usable.
	o.state = state
	got, err = assessLocalAddresses(context.Background(), o, p, [2]uint32{2, 0})
	if err != nil || got.addressFlagsBlocked != 1 {
		return ErrUnavailable
	}
	if got, err := assessLocalAddresses(context.Background(), o, p, [2]uint32{2, 2}); err != ErrUnavailable || got != (localAddressSummary{}) {
		return ErrUnavailable
	}
	copy := *o
	if got, err := assessLocalAddresses(context.Background(), &copy, p, [2]uint32{2, 0}); err != ErrUnavailable || got != (localAddressSummary{}) {
		return ErrUnavailable
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := assessLocalAddresses(ctx, o, p, [2]uint32{2, 0}); err != ErrUnavailable || got != (localAddressSummary{}) {
		return ErrUnavailable
	}
	return nil
}
