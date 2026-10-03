// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package networkinventory

import (
	"encoding/binary"
	"net/netip"

	"golang.org/x/sys/unix"
)

const maxDumpBytes = 1 << 20
const maxDatagramBytes = 64 << 10

type dump struct {
	seq, port        uint32
	kind             uint16
	done             bool
	bytes            int
	links            []link
	addresses        []ipAddress
	routes           []route
	configuredRoutes bool
}

// consume validates complete datagrams; socket sender/truncation checks precede
// it. Every response must belong to the exact private multipart dump.
func (d *dump) consume(data []byte) error {
	if d.done || len(data) < 16 || len(data) > maxDatagramBytes || d.bytes+len(data) > maxDumpBytes {
		return ErrUnavailable
	}
	d.bytes += len(data)
	for len(data) > 0 {
		if len(data) < 16 {
			return ErrUnavailable
		}
		n := int(binary.NativeEndian.Uint32(data[:4]))
		if n < 16 || n > len(data) || align(n) > len(data) {
			return ErrUnavailable
		}
		kind := binary.NativeEndian.Uint16(data[4:6])
		flags := binary.NativeEndian.Uint16(data[6:8])
		allowed := uint16(unix.NLM_F_MULTI)
		// The fixed strict GETROUTE request enumerates configured FIB entries,
		// not cached exceptions. Linux IPv6 explicitly marks that scope FILTERED.
		// This does not permit filters on link/address dumps or arbitrary queries.
		if d.configuredRoutes && d.kind == unix.RTM_NEWROUTE {
			allowed |= unix.NLM_F_DUMP_FILTERED
		}
		if flags & ^allowed != 0 || flags&unix.NLM_F_MULTI == 0 ||
			binary.NativeEndian.Uint32(data[8:12]) != d.seq || binary.NativeEndian.Uint32(data[12:16]) != d.port {
			return ErrUnavailable
		}
		payload := data[16:n]
		if kind == unix.NLMSG_DONE {
			if len(payload) != 4 || binary.NativeEndian.Uint32(payload) != 0 || align(n) != len(data) {
				return ErrUnavailable
			}
			d.done = true
			return nil
		}
		if kind != d.kind {
			return ErrUnavailable
		}
		switch kind {
		case unix.RTM_NEWLINK:
			if len(d.links) >= MaxInterfaces {
				return ErrUnavailable
			}
			l, err := parseLink(payload)
			if err != nil {
				return ErrUnavailable
			}
			d.links = append(d.links, l)
		case unix.RTM_NEWADDR:
			if len(d.addresses) >= MaxAddresses {
				return ErrUnavailable
			}
			a, err := parseAddress(payload)
			if err != nil {
				return ErrUnavailable
			}
			d.addresses = append(d.addresses, a)
		case unix.RTM_NEWROUTE:
			if len(d.routes) >= MaxRoutes {
				return ErrUnavailable
			}
			r, err := parseRoute(payload)
			if err != nil {
				return ErrUnavailable
			}
			d.routes = append(d.routes, r)
		default:
			return ErrUnavailable
		}
		data = data[align(n):]
	}
	return nil
}

func align(n int) int { return (n + 3) &^ 3 }

func attributes(data []byte, known map[uint16]bool) (map[uint16][]byte, error) {
	result := make(map[uint16][]byte, len(known))
	for len(data) > 0 {
		if len(data) < 4 {
			return nil, ErrUnavailable
		}
		n := int(binary.NativeEndian.Uint16(data[:2]))
		kind := binary.NativeEndian.Uint16(data[2:4])
		if n < 4 || n > len(data) || align(n) > len(data) {
			return nil, ErrUnavailable
		}
		base := kind & 0x3fff // Linux NLA_TYPE_MASK; known scalars cannot be nested/network-endian.
		if known[base] {
			if kind != base || result[base] != nil {
				return nil, ErrUnavailable
			}
			result[base] = data[4:n]
		}
		data = data[align(n):]
	}
	return result, nil
}

var linkFields = map[uint16]bool{unix.IFLA_IFNAME: true, unix.IFLA_ADDRESS: true, unix.IFLA_MTU: true, unix.IFLA_MASTER: true, unix.IFLA_LINK: true}
var addressFields = map[uint16]bool{unix.IFA_ADDRESS: true, unix.IFA_LOCAL: true, unix.IFA_FLAGS: true}

func parseLink(data []byte) (link, error) {
	if len(data) < 16 || data[0] != unix.AF_UNSPEC {
		return link{}, ErrUnavailable
	}
	a, err := attributes(data[16:], linkFields)
	if err != nil {
		return link{}, ErrUnavailable
	}
	name := a[unix.IFLA_IFNAME]
	if len(name) < 2 || len(name) > 16 || name[len(name)-1] != 0 || len(a[unix.IFLA_MTU]) != 4 || len(a[unix.IFLA_ADDRESS]) > 32 {
		return link{}, ErrUnavailable
	}
	l := link{index: binary.NativeEndian.Uint32(data[4:8]), kind: binary.NativeEndian.Uint16(data[2:4]),
		name: string(name[:len(name)-1]), flags: binary.NativeEndian.Uint32(data[8:12]), mtu: binary.NativeEndian.Uint32(a[unix.IFLA_MTU]), mac: string(a[unix.IFLA_ADDRESS])}
	for kind, target := range map[uint16]*uint32{unix.IFLA_MASTER: &l.master, unix.IFLA_LINK: &l.lower} {
		if v, ok := a[kind]; ok {
			if len(v) != 4 {
				return link{}, ErrUnavailable
			}
			*target = binary.NativeEndian.Uint32(v)
		}
	}
	return l, nil
}

func parseAddress(data []byte) (ipAddress, error) {
	if len(data) < 8 {
		return ipAddress{}, ErrUnavailable
	}
	size := 4
	switch data[0] {
	case unix.AF_INET:
	case unix.AF_INET6:
		size = 16
	default:
		return ipAddress{}, ErrUnavailable
	}
	if int(data[1]) > size*8 {
		return ipAddress{}, ErrUnavailable
	}
	a, err := attributes(data[8:], addressFields)
	if err != nil || len(a[unix.IFA_ADDRESS]) != size {
		return ipAddress{}, ErrUnavailable
	}
	peer, _ := netip.AddrFromSlice(a[unix.IFA_ADDRESS])
	local := peer
	if v, ok := a[unix.IFA_LOCAL]; ok {
		if len(v) != size {
			return ipAddress{}, ErrUnavailable
		}
		local, _ = netip.AddrFromSlice(v)
	}
	flags := uint32(data[2])
	if v, ok := a[unix.IFA_FLAGS]; ok {
		if len(v) != 4 {
			return ipAddress{}, ErrUnavailable
		}
		flags = binary.NativeEndian.Uint32(v)
		if flags&0xff != uint32(data[2]) {
			return ipAddress{}, ErrUnavailable
		}
	}
	return ipAddress{index: binary.NativeEndian.Uint32(data[4:8]), prefix: netip.PrefixFrom(local, int(data[1])), peer: peer, flags: flags, scope: data[3]}, nil
}
