// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package networkinventory

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"

	"golang.org/x/sys/unix"
)

// Recent Linux 6.18.54 UAPI attributes absent from vendored x/sys.
const (
	ruleDSCP                = 25
	ruleFlowLabel           = 26
	ruleFlowLabelMask       = 27
	ruleSourcePortMask      = 28
	ruleDestinationPortMask = 29
	ruleDSCPMask            = 30
)

func ruleName(value []byte) (string, error) {
	if len(value) < 2 || len(value) > 16 || value[len(value)-1] != 0 {
		return "", ErrUnavailable
	}
	name := string(value[:len(value)-1])
	if !kernelName(name) {
		return "", ErrUnavailable
	}
	return name, nil
}

func parseRule(data []byte) (rule, error) {
	if len(data) < 12 || data[5] != 0 || data[6] != 0 {
		return rule{}, ErrUnavailable
	}
	size := 4
	switch data[0] {
	case unix.AF_INET:
	case unix.AF_INET6:
		size = 16
	default:
		return rule{}, ErrUnavailable
	}
	attrs, err := framedAttributes(data[12:], true, unix.FRA_PAD)
	if err != nil {
		return rule{}, ErrUnavailable
	}
	r := rule{family: data[0], action: data[7], tos: data[3], table: uint32(data[4]), flags: binary.NativeEndian.Uint32(data[8:12])}
	knownFlags := uint32(unix.FIB_RULE_PERMANENT | unix.FIB_RULE_INVERT | unix.FIB_RULE_UNRESOLVED | unix.FIB_RULE_IIF_DETACHED | unix.FIB_RULE_OIF_DETACHED | unix.FIB_RULE_FIND_SADDR)
	r.unresolved = r.flags&^knownFlags != 0 || r.flags&uint32(unix.FIB_RULE_UNRESOLVED|unix.FIB_RULE_IIF_DETACHED|unix.FIB_RULE_OIF_DETACHED) != 0 || r.action != unix.FR_ACT_TO_TBL
	var dst, src []byte
	canonical := bytes.Clone(data[:12])
	for _, a := range attrs {
		base := a.kind & 0x3fff
		known := base == unix.FRA_DST || base == unix.FRA_SRC || base == unix.FRA_IIFNAME || base == unix.FRA_OIFNAME || base == unix.FRA_TABLE || base == unix.FRA_PRIORITY || base == unix.FRA_GOTO || base == unix.FRA_FWMARK || base == unix.FRA_FWMASK || base == unix.FRA_FLOW || base == unix.FRA_TUN_ID || base == unix.FRA_SUPPRESS_IFGROUP || base == unix.FRA_SUPPRESS_PREFIXLEN || base == unix.FRA_L3MDEV || base == unix.FRA_UID_RANGE || base == unix.FRA_PROTOCOL || base == unix.FRA_IP_PROTO || base == unix.FRA_SPORT_RANGE || base == unix.FRA_DPORT_RANGE || base >= ruleDSCP && base <= ruleDSCPMask
		// Pinned kernel emits nla_put_be* without NET_BYTEORDER flags here.
		if known && a.kind != base {
			return rule{}, ErrUnavailable
		}
		switch base {
		case unix.FRA_DST:
			dst = a.value
		case unix.FRA_SRC:
			src = a.value
		case unix.FRA_IIFNAME:
			r.input, err = ruleName(a.value)
		case unix.FRA_OIFNAME:
			r.output, err = ruleName(a.value)
		case unix.FRA_TABLE, unix.FRA_PRIORITY, unix.FRA_GOTO, unix.FRA_FWMARK, unix.FRA_FWMASK, unix.FRA_FLOW, unix.FRA_SUPPRESS_IFGROUP, unix.FRA_SUPPRESS_PREFIXLEN, ruleFlowLabel, ruleFlowLabelMask:
			if len(a.value) != 4 {
				return rule{}, ErrUnavailable
			}
			v := binary.NativeEndian.Uint32(a.value)
			switch base {
			case unix.FRA_TABLE:
				r.table = v
			case unix.FRA_PRIORITY:
				r.priority = v
			case unix.FRA_GOTO:
				r.target = v
				r.unresolved = true
			case unix.FRA_SUPPRESS_PREFIXLEN:
				if v != 0xffffffff && v > uint32(size*8) {
					return rule{}, ErrUnavailable
				}
				if v != 0xffffffff {
					r.unresolved = true
				}
			case ruleFlowLabel, ruleFlowLabelMask:
				if binary.BigEndian.Uint32(a.value) > 0xfffff {
					return rule{}, ErrUnavailable
				}
				r.unresolved = true
			default:
				r.unresolved = true
			}
		case unix.FRA_TUN_ID:
			if len(a.value) != 8 {
				return rule{}, ErrUnavailable
			}
			r.unresolved = true
		case unix.FRA_UID_RANGE:
			if len(a.value) != 8 || binary.NativeEndian.Uint32(a.value[:4]) > binary.NativeEndian.Uint32(a.value[4:]) {
				return rule{}, ErrUnavailable
			}
			r.unresolved = true
		case unix.FRA_SPORT_RANGE, unix.FRA_DPORT_RANGE:
			if len(a.value) != 4 || binary.NativeEndian.Uint16(a.value[:2]) > binary.NativeEndian.Uint16(a.value[2:]) {
				return rule{}, ErrUnavailable
			}
			r.unresolved = true
		case ruleSourcePortMask, ruleDestinationPortMask:
			if len(a.value) != 2 {
				return rule{}, ErrUnavailable
			}
			r.unresolved = true
		case unix.FRA_L3MDEV, unix.FRA_PROTOCOL, unix.FRA_IP_PROTO, ruleDSCP, ruleDSCPMask:
			if len(a.value) != 1 {
				return rule{}, ErrUnavailable
			}
			if base == unix.FRA_L3MDEV && a.value[0] > 1 || (base == ruleDSCP || base == ruleDSCPMask) && a.value[0] > 63 {
				return rule{}, ErrUnavailable
			}
			if base != unix.FRA_PROTOCOL {
				r.unresolved = true
			}
		default:
			r.unresolved = true
		}
		if err != nil {
			return rule{}, ErrUnavailable
		}
		canonical = appendRouteAttribute(canonical, a.kind, a.value)
	}
	r.destination, err = routePrefix(dst, size, int(data[1]))
	if err != nil {
		return rule{}, ErrUnavailable
	}
	r.source, err = routePrefix(src, size, int(data[2]))
	if err != nil {
		return rule{}, ErrUnavailable
	}
	r.semantic = sha256.Sum256(canonical)
	return r, nil
}
