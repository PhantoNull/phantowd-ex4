// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package networkpolicy validates desired network configuration without applying
// it. Logical slots are not qualified hardware identities or kernel names.
package networkpolicy

import (
	"errors"
	"io"
	"net/netip"
	"strings"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/configjson"
)

const (
	Format           = "phantowd-network-policy"
	MaxInputBytes    = 16 << 10
	MaxAddresses     = 4
	MaxRoutes        = 16
	MaxDNSServers    = 3
	MaxSearchDomains = 6
)

var ErrInvalid = errors.New("invalid desired network policy")

type Policy struct {
	Format        string      `json:"format"`
	SchemaVersion int         `json:"schema_version"`
	Revision      uint64      `json:"revision"`
	Hostname      string      `json:"hostname"`
	Interfaces    []Interface `json:"interfaces"`
	Routes        []Route     `json:"routes"`
	DNS           DNS         `json:"dns"`
}

type Interface struct {
	Slot string `json:"slot"`
	IPv4 Family `json:"ipv4"`
	IPv6 Family `json:"ipv6"`
}

type Family struct {
	Mode         string   `json:"mode"`
	Addresses    []string `json:"addresses"`
	DefaultRoute bool     `json:"default_route"`
	Gateway      string   `json:"gateway,omitempty"`
	Metric       uint16   `json:"metric"`
}

type Route struct {
	Slot        string `json:"slot"`
	Destination string `json:"destination"`
	Gateway     string `json:"gateway"`
	Metric      uint16 `json:"metric"`
}

type DNS struct {
	Mode          string   `json:"mode"`
	Source        string   `json:"source,omitempty"`
	Servers       []string `json:"servers"`
	SearchDomains []string `json:"search_domains"`
}

var fields = map[string]bool{
	"format": true, "schema_version": true, "revision": true, "hostname": true,
	"interfaces": true, "slot": true, "ipv4": true, "ipv6": true, "mode": true,
	"addresses": true, "default_route": true, "gateway": true, "metric": true,
	"routes": true, "destination": true, "dns": true, "source": true,
	"servers": true, "search_domains": true,
}

// Decode never returns a partially valid document or echoes untrusted input.
func Decode(input io.Reader) (Policy, error) {
	var p Policy
	if input == nil || configjson.Decode(input, &p, MaxInputBytes, 8, fields) != nil || p.Validate() != nil {
		return Policy{}, ErrInvalid
	}
	return p, nil
}

func (p Policy) Validate() error {
	if p.Format != Format || p.SchemaVersion != 1 || p.Revision == 0 || !label(p.Hostname) ||
		len(p.Interfaces) != 2 || p.Routes == nil || len(p.Routes) > MaxRoutes {
		return ErrInvalid
	}
	var prefixes [2][2][]netip.Prefix
	var defaults [2]uint16
	enabled := false
	for i, port := range p.Interfaces {
		if !slot(port.Slot) || (i == 1 && port.Slot == p.Interfaces[0].Slot) {
			return ErrInvalid
		}
		for family, f := range []Family{port.IPv4, port.IPv6} {
			v4 := family == 0
			parsed, err := validateFamily(f, v4)
			if err != nil {
				return ErrInvalid
			}
			prefixes[i][family] = parsed
			enabled = enabled || f.Mode != "disabled"
			if f.DefaultRoute {
				if defaults[family] == f.Metric {
					return ErrInvalid
				}
				defaults[family] = f.Metric
			}
		}
	}
	if !enabled {
		return ErrInvalid
	}
	for family := range 2 {
		for _, a := range prefixes[0][family] {
			for _, b := range prefixes[1][family] {
				if a.Overlaps(b) {
					return ErrInvalid
				}
			}
		}
	}
	for i, port := range p.Interfaces {
		for family, f := range []Family{port.IPv4, port.IPv6} {
			if f.Gateway != "" && !gateway(f.Gateway, family == 0, prefixes[i][family], prefixes) {
				return ErrInvalid
			}
		}
	}
	for i, r := range p.Routes {
		if len(r.Destination) > 64 {
			return ErrInvalid
		}
		port := p.portIndex(r.Slot)
		destination, err := netip.ParsePrefix(r.Destination)
		if port < 0 || err != nil || destination.String() != r.Destination ||
			destination != destination.Masked() || destination.Bits() == 0 ||
			!unicast(destination.Addr(), false) || r.Metric == 0 {
			return ErrInvalid
		}
		family := 1
		mode := p.Interfaces[port].IPv6.Mode
		if destination.Addr().Is4() {
			family = 0
			mode = p.Interfaces[port].IPv4.Mode
		}
		if mode != "static" || !gateway(r.Gateway, family == 0, prefixes[port][family], prefixes) {
			return ErrInvalid
		}
		for _, old := range p.Routes[:i] {
			if old.Destination == r.Destination && old.Metric == r.Metric {
				return ErrInvalid
			}
		}
	}
	return p.validateDNS()
}

func validateFamily(f Family, v4 bool) ([]netip.Prefix, error) {
	if f.Addresses == nil || len(f.Addresses) > MaxAddresses {
		return nil, ErrInvalid
	}
	switch f.Mode {
	case "disabled":
		if len(f.Addresses) != 0 || f.DefaultRoute || f.Gateway != "" || f.Metric != 0 {
			return nil, ErrInvalid
		}
		return nil, nil
	case "dhcp":
		if !v4 {
			return nil, ErrInvalid
		}
	case "auto":
		if v4 {
			return nil, ErrInvalid
		}
	case "static":
		if len(f.Addresses) == 0 {
			return nil, ErrInvalid
		}
	default:
		return nil, ErrInvalid
	}
	if f.DefaultRoute != (f.Metric != 0) ||
		(f.Gateway != "" && (f.Mode != "static" || !f.DefaultRoute)) ||
		(f.Mode == "static" && f.DefaultRoute && f.Gateway == "") ||
		(f.Mode != "static" && len(f.Addresses) != 0) {
		return nil, ErrInvalid
	}
	parsed := make([]netip.Prefix, 0, len(f.Addresses))
	for _, value := range f.Addresses {
		if len(value) > 64 {
			return nil, ErrInvalid
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.String() != value || prefix.Bits() == 0 ||
			prefix.Addr().Is4() != v4 || !unicast(prefix.Addr(), false) ||
			(v4 && !ipv4Host(prefix)) {
			return nil, ErrInvalid
		}
		for _, old := range parsed {
			if old.Addr() == prefix.Addr() {
				return nil, ErrInvalid
			}
		}
		parsed = append(parsed, prefix)
	}
	return parsed, nil
}

func (p Policy) validateDNS() error {
	d := p.DNS
	if d.Servers == nil || d.SearchDomains == nil || len(d.Servers) > MaxDNSServers ||
		len(d.SearchDomains) > MaxSearchDomains {
		return ErrInvalid
	}
	switch d.Mode {
	case "manual":
		if d.Source != "" || len(d.Servers) == 0 {
			return ErrInvalid
		}
	case "automatic":
		i := p.portIndex(d.Source)
		if i < 0 || len(d.Servers) != 0 ||
			(p.Interfaces[i].IPv4.Mode != "dhcp" && p.Interfaces[i].IPv6.Mode != "auto") {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	for i, value := range d.Servers {
		addr, ok := address(value)
		if !ok || !(unicast(addr, false) || addr.IsLoopback()) {
			return ErrInvalid
		}
		for _, old := range d.Servers[:i] {
			if old == value {
				return ErrInvalid
			}
		}
	}
	for i, domain := range d.SearchDomains {
		if len(domain) > 253 || len(domain) == 0 {
			return ErrInvalid
		}
		for _, part := range strings.Split(domain, ".") {
			if !label(part) {
				return ErrInvalid
			}
		}
		for _, old := range d.SearchDomains[:i] {
			if old == domain {
				return ErrInvalid
			}
		}
	}
	return nil
}

func (p Policy) portIndex(value string) int {
	if !slot(value) {
		return -1
	}
	for i, port := range p.Interfaces {
		if port.Slot == value {
			return i
		}
	}
	return -1
}

func slot(value string) bool { return value == "lan-1" || value == "lan-2" }

func label(value string) bool {
	if len(value) == 0 || len(value) > 63 || value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

func address(value string) (netip.Addr, bool) {
	if len(value) > 64 {
		return netip.Addr{}, false
	}
	a, err := netip.ParseAddr(value)
	return a, err == nil && a.Zone() == "" && !a.Is4In6() && a.String() == value
}

func unicast(a netip.Addr, linkLocal bool) bool {
	if !a.IsValid() || a.Zone() != "" || a.Is4In6() || a.IsLoopback() {
		return false
	}
	if !a.Is4() {
		// Limit static IPv6 to global 2000::/3 and ULA fc00::/7; Go's
		// IsGlobalUnicast also includes unsupported/reserved address space.
		b := a.As16()
		return b[0]&0xe0 == 0x20 || b[0]&0xfe == 0xfc || linkLocal && a.IsLinkLocalUnicast()
	}
	b := a.As4()
	return a.IsGlobalUnicast() && !a.IsLinkLocalUnicast() && b[0] != 0 && b[0] < 224
}

func ipv4Host(p netip.Prefix) bool {
	if p.Bits() >= 31 {
		return true
	}
	b := p.Addr().As4()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	hostMask := ^uint32(0) >> uint(p.Bits())
	return v&hostMask != 0 && v&hostMask != hostMask
}

func gateway(value string, v4 bool, onLink []netip.Prefix, all [2][2][]netip.Prefix) bool {
	a, ok := address(value)
	if !ok || a.Is4() != v4 || !unicast(a, !v4) {
		return false
	}
	for _, port := range all {
		for _, family := range port {
			for _, p := range family {
				if p.Addr() == a {
					return false
				}
			}
		}
	}
	if !v4 && a.IsLinkLocalUnicast() {
		return true
	}
	for _, p := range onLink {
		if p.Contains(a) && (!v4 || ipv4Host(netip.PrefixFrom(a, p.Bits()))) {
			return true
		}
	}
	return false
}
