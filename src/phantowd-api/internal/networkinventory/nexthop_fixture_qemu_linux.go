//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package networkinventory

import (
	"encoding/binary"
	"slices"

	"golang.org/x/sys/unix"
)

// QEMUObjectFixture checks nonempty generated wire objects on the actual guest
// CPU. It neither creates kernel objects nor returns observation authority.
// Actual kernel collection is a separate mandatory self-test, possibly empty.
func QEMUObjectFixture() error {
	attribute := func(kind uint16, value []byte) []byte {
		p := make([]byte, align(4+len(value)))
		binary.NativeEndian.PutUint16(p, uint16(4+len(value)))
		binary.NativeEndian.PutUint16(p[2:], kind)
		copy(p[4:], value)
		return p
	}
	u32 := func(v uint32) []byte {
		p := make([]byte, 4)
		binary.NativeEndian.PutUint32(p, v)
		return p
	}
	member := func(id, weight uint32) []byte { return append(u32(id), byte(weight-1), byte((weight-1)>>8), 0, 0) }
	object := func(family byte, id uint32, fields ...[]byte) []byte {
		p := append([]byte{family, 0, 4, 0, 0, 0, 0, 0}, attribute(nhaID, u32(id))...)
		for _, f := range fields {
			p = append(p, f...)
		}
		return p
	}
	first, e1 := parseNextHopObject(object(unix.AF_INET, 7, attribute(nhaOIF, u32(1)), attribute(nhaGateway, []byte{192, 0, 2, 1})))
	second, e2 := parseNextHopObject(object(unix.AF_INET6, 8, attribute(nhaOIF, u32(1)), attribute(nhaGateway, []byte{0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})))
	groupWire := func(members []byte) []byte {
		return object(0, 20, attribute(nhaGroup, members), attribute(nhaGroupType, []byte{0, 0}), attribute(nhaOpFlags, u32(1<<31)))
	}
	group, e3 := parseNextHopObject(groupWire(append(member(7, 257), member(8, 65535)...)))
	reversed, e4 := parseNextHopObject(groupWire(append(member(8, 65535), member(7, 257)...)))
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || group.semantic == reversed.semantic || group.members[0].weight != 257 || group.members[1].weight != 65535 || first.gateway.String() != "192.0.2.1" || second.gateway.String() != "2001:db8::1" {
		return ErrUnavailable
	}
	a := snapshot{links: []link{{index: 1, name: "lo"}}, addresses: []ipAddress{}, routes: []route{}, rules: []rule{}, objects: []nextHopObject{first, second, group}}
	b := a
	b.objects = slices.Clone(a.objects)
	slices.Reverse(b.objects)
	if normalize(&a) != nil || normalize(&b) != nil || !equal(a, b) {
		return ErrUnavailable
	}
	b.objects[2] = reversed
	if equal(a, b) {
		return ErrUnavailable
	}
	bad := a
	bad.objects = slices.Clone(a.objects[:2])
	bad.objects = append(bad.objects, group)
	bad.objects[2].members = slices.Clone(group.members)
	bad.objects[2].members[0].id = 99
	if normalize(&bad) != ErrUnavailable {
		return ErrUnavailable
	}
	return nil
}
