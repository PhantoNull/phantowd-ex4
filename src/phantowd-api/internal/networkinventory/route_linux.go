// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package networkinventory

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"net/netip"
	"slices"

	"golang.org/x/sys/unix"
)

// RTA_NH_ID is not named by the vendored x/sys version. Its ABI value is
// verified against the pinned Linux 6.18.54 UAPI, not guessed from tool prose.
const routeNextHopID = 30
const maxRouteAttributes = 128

type routeAttribute struct {
	kind  uint16
	value []byte
}

// routeAttributes retains unknown types (including their flags) for private
// comparison rather than silently discarding semantics we cannot interpret.
func routeAttributes(data []byte, padding bool) ([]routeAttribute, error) {
	result := []routeAttribute{}
	seen := make(map[uint16]bool)
	for len(data) > 0 {
		if len(data) < 4 || len(result) >= maxRouteAttributes {
			return nil, ErrUnavailable
		}
		n := int(binary.NativeEndian.Uint16(data[:2]))
		kind := binary.NativeEndian.Uint16(data[2:4])
		base := kind & 0x3fff
		if n < 4 || n > len(data) || align(n) > len(data) {
			return nil, ErrUnavailable
		}
		// Padding is not route semantics; repeated empty PAD is harmless.
		if padding && kind == unix.RTA_PAD && n == 4 {
			data = data[align(n):]
			continue
		}
		if seen[base] {
			return nil, ErrUnavailable
		}
		seen[base] = true
		result = append(result, routeAttribute{kind, data[4:n]})
		data = data[align(n):]
	}
	slices.SortFunc(result, func(a, b routeAttribute) int { return int(a.kind) - int(b.kind) })
	return result, nil
}

// Explicit type and length delimiters prevent ambiguity in opaque comparison.
func appendRouteAttribute(dst []byte, kind uint16, value []byte) []byte {
	dst = binary.LittleEndian.AppendUint16(dst, kind)
	dst = binary.LittleEndian.AppendUint32(dst, uint32(len(value)))
	return append(dst, value...)
}

func routeAddress(data []byte, size int) (netip.Addr, error) {
	if len(data) != size {
		return netip.Addr{}, ErrUnavailable
	}
	a, ok := netip.AddrFromSlice(data)
	if !ok {
		return netip.Addr{}, ErrUnavailable
	}
	return a, nil
}

func routePrefix(data []byte, size, bits int) (netip.Prefix, error) {
	if bits > size*8 {
		return netip.Prefix{}, ErrUnavailable
	}
	if data == nil && bits == 0 {
		data = make([]byte, size)
	}
	a, err := routeAddress(data, size)
	if err != nil {
		return netip.Prefix{}, err
	}
	p := netip.PrefixFrom(a, bits)
	if p != p.Masked() {
		return netip.Prefix{}, ErrUnavailable
	}
	return p, nil
}

func routeIndex(data []byte) (uint32, error) {
	if len(data) != 4 {
		return 0, ErrUnavailable
	}
	i := binary.NativeEndian.Uint32(data)
	if i == 0 || i > 0x7fffffff {
		return 0, ErrUnavailable
	}
	return i, nil
}

func routeVia(data []byte) (netip.Addr, error) {
	if len(data) < 2 {
		return netip.Addr{}, ErrUnavailable
	}
	size := 4
	switch binary.NativeEndian.Uint16(data[:2]) {
	case unix.AF_INET:
	case unix.AF_INET6:
		size = 16
	default:
		return netip.Addr{}, ErrUnavailable
	}
	return routeAddress(data[2:], size)
}

func parseRoute(data []byte) (route, error) {
	if len(data) < 12 {
		return route{}, ErrUnavailable
	}
	size := 4
	switch data[0] {
	case unix.AF_INET:
	case unix.AF_INET6:
		size = 16
	default:
		return route{}, ErrUnavailable
	}
	attrs, err := routeAttributes(data[12:], true)
	if err != nil {
		return route{}, ErrUnavailable
	}
	r := route{table: uint32(data[4]), protocol: data[5], scope: data[6], kind: data[7], tos: data[3], flags: binary.NativeEndian.Uint32(data[8:12]), next: []nextHop{}}
	var dst, src []byte
	canonical := bytes.Clone(data[:12])
	for _, a := range attrs {
		value := a.value
		base := a.kind & 0x3fff
		// Supported fields have native-endian scalars and explicit nesting rules.
		if base <= unix.RTA_PRIORITY || base == unix.RTA_PREFSRC || base == unix.RTA_MULTIPATH || base == unix.RTA_TABLE || base == unix.RTA_CACHEINFO || base == unix.RTA_VIA || base == unix.RTA_EXPIRES || base == routeNextHopID || base == unix.RTA_PREF {
			if a.kind != base {
				return route{}, ErrUnavailable
			}
		}
		switch base {
		case unix.RTA_DST:
			dst = value
		case unix.RTA_SRC:
			src = value
		case unix.RTA_IIF:
			r.input, err = routeIndex(value)
		case unix.RTA_OIF:
			r.output, err = routeIndex(value)
		case unix.RTA_GATEWAY:
			r.gateway, err = routeAddress(value, size)
		case unix.RTA_PREFSRC:
			r.preferred, err = routeAddress(value, size)
		case unix.RTA_PRIORITY, unix.RTA_TABLE, routeNextHopID:
			if len(value) != 4 {
				return route{}, ErrUnavailable
			}
			scalar := binary.NativeEndian.Uint32(value)
			if base == unix.RTA_PRIORITY {
				r.metric = scalar
			}
			if base == unix.RTA_TABLE {
				r.table = scalar
			}
			if base == routeNextHopID {
				if scalar == 0 {
					return route{}, ErrUnavailable
				}
				r.unresolved = true // The referenced nexthop object was not dumped.
			}
		case unix.RTA_VIA:
			r.via, err = routeVia(value)
		case unix.RTA_PREF:
			if len(value) != 1 {
				return route{}, ErrUnavailable
			}
		case unix.RTA_MULTIPATH:
			r.next, value, err = parseNextHops(value, size)
			for _, n := range r.next {
				r.unresolved = r.unresolved || n.unresolved
			}
		case unix.RTA_METRICS:
			// Metrics are not interpreted yet, but malformed nesting and duplicate
			// keys are refused and their order does not cause false route drift.
			if a.kind != base && a.kind != base|0x8000 {
				return route{}, ErrUnavailable
			}
			var nested []routeAttribute
			nested, err = routeAttributes(value, false)
			value = nil
			for _, m := range nested {
				value = appendRouteAttribute(value, m.kind, m.value)
			}
			r.unresolved = true
		case unix.RTA_CACHEINFO:
			if len(value) != 32 {
				return route{}, ErrUnavailable
			}
			// Usage, expiry and timestamps change without a configuration change.
			// Keep the reported error, but do not imply expiry/freshness authority.
			value = value[12:16]
		case unix.RTA_EXPIRES:
			if len(value) != 4 {
				return route{}, ErrUnavailable
			}
			continue
		default:
			r.unresolved = true
		}
		if err != nil {
			return route{}, ErrUnavailable
		}
		canonical = appendRouteAttribute(canonical, a.kind, value)
	}
	r.destination, err = routePrefix(dst, size, int(data[1]))
	if err != nil {
		return route{}, ErrUnavailable
	}
	r.source, err = routePrefix(src, size, int(data[2]))
	if err != nil {
		return route{}, ErrUnavailable
	}
	// Unknown route kinds are retained, never described as usable unicast.
	if r.kind == 0 || r.kind > unix.RTN_XRESOLVE {
		r.unresolved = true
	}
	r.semantic = sha256.Sum256(canonical)
	return r, nil
}

func parseNextHops(data []byte, size int) ([]nextHop, []byte, error) {
	result := []nextHop{}
	for len(data) > 0 {
		if len(data) < 8 || len(result) >= maxNextHops {
			return nil, nil, ErrUnavailable
		}
		n := int(binary.NativeEndian.Uint16(data[:2]))
		if n < 8 || n > len(data) || align(n) > len(data) {
			return nil, nil, ErrUnavailable
		}
		index, err := routeIndex(data[4:8])
		if err != nil {
			return nil, nil, ErrUnavailable
		}
		nh := nextHop{index: index, flags: data[2], hops: data[3]}
		attrs, err := routeAttributes(data[8:n], true)
		if err != nil {
			return nil, nil, ErrUnavailable
		}
		canonical := bytes.Clone(data[2:8])
		for _, a := range attrs {
			switch a.kind {
			case unix.RTA_GATEWAY:
				nh.gateway, err = routeAddress(a.value, size)
			case unix.RTA_VIA:
				nh.via, err = routeVia(a.value)
			default:
				nh.unresolved = true
			}
			if (a.kind&0x3fff == unix.RTA_GATEWAY || a.kind&0x3fff == unix.RTA_VIA) && a.kind&0xc000 != 0 {
				return nil, nil, ErrUnavailable
			}
			if err != nil {
				return nil, nil, ErrUnavailable
			}
			canonical = appendRouteAttribute(canonical, a.kind, a.value)
		}
		nh.semantic = sha256.Sum256(canonical)
		result = append(result, nh)
		data = data[align(n):]
	}
	if len(result) == 0 {
		return nil, nil, ErrUnavailable
	}
	slices.SortFunc(result, func(a, b nextHop) int { return bytes.Compare(a.semantic[:], b.semantic[:]) })
	canonical := []byte{}
	for i, n := range result {
		if i > 0 && result[i-1].semantic == n.semantic {
			return nil, nil, ErrUnavailable
		}
		canonical = append(canonical, n.semantic[:]...)
	}
	return result, canonical, nil
}
