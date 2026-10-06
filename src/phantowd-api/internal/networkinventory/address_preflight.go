// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package networkinventory

import (
	"context"
	"net/netip"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/networkpolicy"
)

// This is deliberately private: no product factory-binding provider exists.
// Counts are overlapping point-in-time diagnostics, never admission authority.
type localAddressSummary struct {
	static, exact, missing, addressElsewhere, peerElsewhere, overlapElsewhere int
	addressFlagsBlocked, linkFlagsBlocked, localGateways, dynamic, unbound    int
}

// ifindices are transient lan-1/lan-2 bindings, not names or stable identities.
func assessLocalAddresses(ctx context.Context, o *Observation, p networkpolicy.Policy, ifindices [2]uint32) (localAddressSummary, error) {
	var result localAddressSummary
	if ctx == nil || ctx.Err() != nil || o == nil || o.self != o || p.Validate() != nil {
		return result, ErrUnavailable
	}
	if ifindices[0] != 0 && ifindices[0] == ifindices[1] {
		return result, ErrUnavailable
	}
	gateways := map[struct {
		index uint32
		addr  netip.Addr
	}]bool{}
	checkGateway := func(index uint32, text string) {
		if text == "" {
			return
		}
		addr, _ := netip.ParseAddr(text) // The complete policy was validated.
		key := struct {
			index uint32
			addr  netip.Addr
		}{index, addr}
		if gateways[key] {
			return
		}
		gateways[key] = true
		for _, current := range o.state.addresses {
			if current.prefix.Addr() == addr && (!addr.IsLinkLocalUnicast() || current.index == index) {
				result.localGateways++
				return
			}
		}
	}
	for _, port := range p.Interfaces {
		slot := 0
		if port.Slot == "lan-2" {
			slot = 1
		}
		index := ifindices[slot]
		if index == 0 {
			if port.IPv4.Mode != "disabled" || port.IPv6.Mode != "disabled" {
				return localAddressSummary{}, ErrUnavailable
			}
			result.unbound++
			continue
		}
		var bound *link
		for i := range o.state.links {
			if o.state.links[i].index == index {
				bound = &o.state.links[i]
				break
			}
		}
		if bound == nil || bound.kind != 1 || bound.flags&8 != 0 || bound.master != 0 || bound.lower != 0 ||
			len(bound.mac) != 6 || bound.mac[0]&1 != 0 || bound.mac == "\x00\x00\x00\x00\x00\x00" {
			return localAddressSummary{}, ErrUnavailable
		}
		for _, family := range []networkpolicy.Family{port.IPv4, port.IPv6} {
			if family.Mode == "dhcp" || family.Mode == "auto" {
				result.dynamic++
			}
			if family.Mode == "disabled" {
				continue
			}
			if bound.flags&1 == 0 || bound.flags&0x10000 == 0 || bound.flags&0x20000 != 0 {
				result.linkFlagsBlocked++
			}
			checkGateway(index, family.Gateway)
			for _, text := range family.Addresses {
				wanted, _ := netip.ParsePrefix(text)
				result.static++
				exact, addressUse, peerUse, overlap, badState := false, false, false, false, false
				for _, current := range o.state.addresses {
					if current.index != index {
						addressUse = addressUse || current.prefix.Addr() == wanted.Addr()
						peerUse = peerUse || current.peer != current.prefix.Addr() && current.peer == wanted.Addr()
						overlap = overlap || wanted.Overlaps(current.prefix)
						continue
					}
					if current.prefix == wanted {
						exact = true
						allowed := uint32(0x80 | 0x200) // Linux 6.18 IFA_F_* UAPI.
						if wanted.Addr().Is4() {
							allowed |= 1 // SECONDARY is an IPv4 alias, IPv6 TEMPORARY.
						}
						badState = badState || current.scope != 0 || current.peer != wanted.Addr() || current.flags & ^allowed != 0
					}
				}
				if exact {
					result.exact++
				} else {
					result.missing++
				}
				if addressUse {
					result.addressElsewhere++
				}
				if peerUse {
					result.peerElsewhere++
				}
				if overlap {
					result.overlapElsewhere++
				}
				if badState {
					result.addressFlagsBlocked++
				}
			}
		}
	}
	for _, route := range p.Routes {
		slot := 0
		if route.Slot == "lan-2" {
			slot = 1
		}
		checkGateway(ifindices[slot], route.Gateway)
	}
	if ctx.Err() != nil {
		return localAddressSummary{}, ErrUnavailable
	}
	return result, nil
}
