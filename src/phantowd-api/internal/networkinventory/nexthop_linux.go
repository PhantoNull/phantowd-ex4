// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package networkinventory

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"

	"golang.org/x/sys/unix"
)

// Independent ABI framing, pinned to Linux 6.18.54 include/uapi/linux/nexthop.h.
// The vendored x/sys names RTM_*NEXTHOP but not these NHA attributes.
const (
	nhaID            = 1
	nhaGroup         = 2
	nhaGroupType     = 3
	nhaBlackhole     = 4
	nhaOIF           = 5
	nhaGateway       = 6
	nhaEncapType     = 7
	nhaEncap         = 8
	nhaGroups        = 9
	nhaMaster        = 10
	nhaFDB           = 11
	nhaResGroup      = 12
	nhaResBucket     = 13
	nhaOpFlags       = 14
	nhaGroupStats    = 15
	nhaHWStatsEnable = 16
	nhaHWStatsUsed   = 17
)

func parseNextHopObject(data []byte) (nextHopObject, error) {
	if len(data) < 8 || len(data) > maxDatagramBytes || data[3] != 0 || data[0] != unix.AF_UNSPEC && data[0] != unix.AF_INET && data[0] != unix.AF_INET6 {
		return nextHopObject{}, ErrUnavailable
	}
	attrs, err := framedAttributes(data[8:], false, 0)
	if err != nil {
		return nextHopObject{}, ErrUnavailable
	}
	n := nextHopObject{family: data[0], scope: data[1], protocol: data[2], flags: binary.NativeEndian.Uint32(data[4:8])}
	canonical := bytes.Clone(data[:8])
	var groupType, resGroup, encap, encapType, opFlags bool
	for _, a := range attrs {
		base, value := a.kind&0x3fff, a.value
		if base >= nhaID && base <= nhaHWStatsUsed {
			if base == nhaEncap {
				// lwtunnel_fill_encap uses nla_nest_start_noflag; also accept
				// explicit nesting, never network-endian flags on this framing.
				if a.kind != base && a.kind != base|0x8000 {
					return nextHopObject{}, ErrUnavailable
				}
			} else if base == nhaResGroup {
				if a.kind != base|0x8000 {
					return nextHopObject{}, ErrUnavailable
				}
			} else if a.kind != base {
				return nextHopObject{}, ErrUnavailable
			}
		}
		switch base {
		case nhaID:
			if len(value) != 4 {
				return nextHopObject{}, ErrUnavailable
			}
			n.id = binary.NativeEndian.Uint32(value)
		case nhaOIF:
			n.output, err = routeIndex(value)
		case nhaGateway:
			size := 4
			if n.family == unix.AF_INET6 {
				size = 16
			}
			if n.family == unix.AF_UNSPEC {
				return nextHopObject{}, ErrUnavailable
			}
			n.gateway, err = routeAddress(value, size)
		case nhaBlackhole, nhaFDB:
			if len(value) != 0 {
				return nextHopObject{}, ErrUnavailable
			}
			if base == nhaBlackhole {
				n.blackhole = true
			} else {
				n.fdb, n.unresolved = true, true
			}
		case nhaGroup:
			if len(value) == 0 || len(value)%8 != 0 || len(value)/8 > maxNextHops {
				return nextHopObject{}, ErrUnavailable
			}
			n.members = make([]nextHopMember, 0, len(value)/8)
			for offset := 0; offset < len(value); offset += 8 {
				id := binary.NativeEndian.Uint32(value[offset:])
				weight := uint32(value[offset+4]) | uint32(value[offset+5])<<8
				if id == 0 || weight == 65535 || binary.NativeEndian.Uint16(value[offset+6:]) != 0 {
					return nextHopObject{}, ErrUnavailable
				}
				for _, old := range n.members {
					if old.id == id {
						return nextHopObject{}, ErrUnavailable
					}
				}
				n.members = append(n.members, nextHopMember{id, weight + 1})
			}
		case nhaGroupType:
			if len(value) != 2 {
				return nextHopObject{}, ErrUnavailable
			}
			groupType = true
			n.groupType = binary.NativeEndian.Uint16(value)
			n.unresolved = n.unresolved || n.groupType != 0
		case nhaOpFlags:
			if len(value) != 4 || binary.NativeEndian.Uint32(value) != 1<<31 {
				return nextHopObject{}, ErrUnavailable
			}
			opFlags = true
		case nhaResGroup:
			resGroup, n.unresolved = true, true
			value, err = canonicalResilientGroup(value)
		case nhaEncapType:
			if len(value) != 2 {
				return nextHopObject{}, ErrUnavailable
			}
			encapType, n.unresolved = true, true
		case nhaEncap:
			encap, n.unresolved = true, true
			var nested []routeAttribute
			nested, err = framedAttributes(value, false, 0)
			if len(nested) == 0 {
				return nextHopObject{}, ErrUnavailable
			}
			value = nil
			for _, entry := range nested {
				value = appendRouteAttribute(value, entry.kind, entry.value)
			}
		case nhaGroups, nhaMaster, nhaResBucket, nhaGroupStats, nhaHWStatsEnable, nhaHWStatsUsed:
			// Query-only selectors and unrequested bucket/statistics responses
			// are outside this fixed no-stats object dump.
			return nextHopObject{}, ErrUnavailable
		default:
			n.unresolved = true
		}
		if err != nil {
			return nextHopObject{}, ErrUnavailable
		}
		canonical = appendRouteAttribute(canonical, a.kind, value)
	}
	if n.id == 0 || encap != encapType {
		return nextHopObject{}, ErrUnavailable
	}
	if len(n.members) != 0 {
		if n.family != unix.AF_UNSPEC || n.scope != 0 || !groupType || !opFlags || n.output != 0 || n.gateway.IsValid() || n.blackhole || encap || (n.groupType == 1) != resGroup {
			return nextHopObject{}, ErrUnavailable
		}
	} else {
		if groupType || resGroup || opFlags || n.family == unix.AF_UNSPEC {
			return nextHopObject{}, ErrUnavailable
		}
		if n.blackhole {
			if n.fdb || n.output != 0 || n.gateway.IsValid() || encap {
				return nextHopObject{}, ErrUnavailable
			}
		} else if n.fdb {
			if n.output != 0 || encap || !n.gateway.IsValid() {
				return nextHopObject{}, ErrUnavailable
			}
		} else if n.output == 0 {
			return nextHopObject{}, ErrUnavailable
		}
	}
	n.semantic = sha256.Sum256(canonical)
	return n, nil
}

func canonicalResilientGroup(data []byte) ([]byte, error) {
	attrs, err := framedAttributes(data, true, 0)
	if err != nil {
		return nil, ErrUnavailable
	}
	canonical := []byte{}
	var seen uint8
	for _, a := range attrs {
		base := a.kind & 0x3fff
		if base <= 4 && a.kind != base {
			return nil, ErrUnavailable
		}
		switch base {
		case 0:
			return nil, ErrUnavailable // only empty PAD is allowed (handled above)
		case 1:
			if len(a.value) != 2 || binary.NativeEndian.Uint16(a.value) == 0 {
				return nil, ErrUnavailable
			}
		case 2, 3:
			if len(a.value) != 4 {
				return nil, ErrUnavailable
			}
		case 4:
			if len(a.value) != 8 {
				return nil, ErrUnavailable
			}
		}
		if base >= 1 && base <= 4 {
			seen |= 1 << base
		}
		if base != 4 {
			canonical = appendRouteAttribute(canonical, a.kind, a.value)
		}
	}
	if seen != 0x1e {
		return nil, ErrUnavailable
	}
	return canonical, nil
}
