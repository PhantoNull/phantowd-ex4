// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package networkinventory

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"math/rand/v2"
	"net/netip"
	"slices"
	"testing"

	"golang.org/x/sys/unix"
)

func objectPayload(family byte, id uint32, attributes ...[]byte) []byte {
	p := []byte{family, 0, 4, 0, 0, 0, 0, 0}
	p = append(p, attr(nhaID, u32(id))...)
	for _, a := range attributes {
		p = append(p, a...)
	}
	return p
}

func objectMember(id, weight uint32) []byte {
	return append(u32(id), byte(weight-1), byte((weight-1)>>8), 0, 0)
}

func objectGroup(id uint32, members ...[]byte) []byte {
	return objectPayload(unix.AF_UNSPEC, id, attr(nhaGroup, bytes.Join(members, nil)), attr(nhaGroupType, []byte{0, 0}), attr(nhaOpFlags, u32(1<<31)))
}

func mustObject(t *testing.T, p []byte) nextHopObject {
	t.Helper()
	n, e := parseNextHopObject(p)
	if e != nil {
		t.Fatal("valid object rejected", e)
	}
	return n
}

func TestNextHopRequestIsFixedUnfilteredWithoutStats(t *testing.T) {
	m, e := requestMessage(unix.RTM_GETNEXTHOP, unix.RTM_NEWNEXTHOP, unix.AF_UNSPEC, 7)
	if e != nil || len(m) != 24 || binary.NativeEndian.Uint32(m) != 24 || binary.NativeEndian.Uint16(m[4:]) != unix.RTM_GETNEXTHOP || binary.NativeEndian.Uint16(m[6:]) != unix.NLM_F_REQUEST|unix.NLM_F_DUMP || binary.NativeEndian.Uint32(m[8:]) != 7 || !bytes.Equal(m[12:], make([]byte, 12)) {
		t.Fatal("nexthop request scope")
	}
	for _, family := range []byte{unix.AF_INET, unix.AF_INET6, 128, 255} {
		if _, e := requestMessage(unix.RTM_GETNEXTHOP, unix.RTM_NEWNEXTHOP, family, 7); e != ErrUnavailable {
			t.Fatal("filtered object request accepted")
		}
	}
	for _, pair := range [][2]uint16{{unix.RTM_NEWNEXTHOP, unix.RTM_NEWNEXTHOP}, {unix.RTM_GETNEXTHOP, unix.RTM_NEWNEXTHOPBUCKET}, {unix.RTM_GETNEXTHOPBUCKET, unix.RTM_NEWNEXTHOP}} {
		if _, e := requestMessage(pair[0], pair[1], 0, 7); e != ErrUnavailable {
			t.Fatal("undeclared object request")
		}
	}
}

func TestNextHopSingleGroupFieldsOrderingAndWeights(t *testing.T) {
	a := mustObject(t, objectPayload(unix.AF_INET, 7, attr(nhaOIF, u32(2)), attr(nhaGateway, []byte{192, 0, 2, 1})))
	b := mustObject(t, objectPayload(unix.AF_INET, 7, attr(nhaGateway, []byte{192, 0, 2, 1}), attr(nhaOIF, u32(2))))
	if a.id != 7 || a.output != 2 || a.gateway.String() != "192.0.2.1" || a.family != unix.AF_INET || a.protocol != 4 || a.unresolved || a.semantic != b.semantic {
		t.Fatal("single semantics or attribute order")
	}
	ip6 := netip.MustParseAddr("2001:db8::1").As16()
	c := mustObject(t, objectPayload(unix.AF_INET6, 8, attr(nhaOIF, u32(1)), attr(nhaGateway, ip6[:])))
	if c.gateway.String() != "2001:db8::1" || c.unresolved {
		t.Fatal("IPv6 gateway")
	}
	black := mustObject(t, objectPayload(unix.AF_INET, 9, attr(nhaBlackhole, nil)))
	if !black.blackhole || black.output != 0 || black.unresolved {
		t.Fatal("blackhole semantics")
	}
	fdb := mustObject(t, objectPayload(unix.AF_INET6, 10, attr(nhaFDB, nil), attr(nhaGateway, ip6[:])))
	if !fdb.fdb || !fdb.unresolved {
		t.Fatal("FDB must remain unresolved")
	}
	g := mustObject(t, objectGroup(20, objectMember(7, 257), objectMember(8, 65535)))
	h := mustObject(t, objectGroup(20, objectMember(8, 65535), objectMember(7, 257)))
	if g.unresolved || len(g.members) != 2 || g.members[0] != (nextHopMember{7, 257}) || g.members[1].weight != 65535 || g.semantic == h.semantic {
		t.Fatal("ordered 16-bit group semantics")
	}
	for _, attribute := range [][]byte{attr(500|0x8000, []byte{1}), attr(nhaEncapType, []byte{1, 0})} {
		p := objectPayload(unix.AF_INET, 7, attribute, attr(nhaOIF, u32(2)))
		if binary.NativeEndian.Uint16(attribute[2:]) == nhaEncapType {
			p = append(p /* nested independent fixture */, objectEncap()...)
		}
		if !mustObject(t, p).unresolved {
			t.Fatal("unknown encapsulation semantics hidden")
		}
	}
}

func objectEncap() []byte { return attr(nhaEncap|0x8000, attr(1, []byte{1, 2})) }

func TestNextHopPinnedKernelEncapsulationUsesNoFlagNest(t *testing.T) {
	// net/core/lwtunnel.c lwtunnel_fill_encap uses nla_nest_start_noflag.
	p := objectPayload(unix.AF_INET, 7, attr(nhaOIF, u32(2)), attr(nhaEncapType, []byte{1, 0}), attr(nhaEncap, attr(1, []byte{1, 2})))
	if !mustObject(t, p).unresolved {
		t.Fatal("encapsulation admitted as plain nexthop")
	}
}

func resilientAttrs(counter byte) []byte {
	return bytes.Join([][]byte{attr(1, []byte{32, 0}), attr(2, u32(12000)), attr(3, u32(0)), attr(0, nil), attr(4, []byte{counter, 0, 0, 0, 0, 0, 0, 0})}, nil)
}

func resilientObject(counter byte) []byte {
	return objectPayload(0, 20, attr(nhaGroup, objectMember(7, 1)), attr(nhaGroupType, []byte{1, 0}), attr(nhaOpFlags, u32(1<<31)), attr(nhaResGroup|0x8000, resilientAttrs(counter)))
}

func TestNextHopResilientCanonicalCountersAndConfiguration(t *testing.T) {
	a, b := mustObject(t, resilientObject(1)), mustObject(t, resilientObject(2))
	if !a.unresolved || a.semantic != b.semantic {
		t.Fatal("resilient incomplete/counter semantics")
	}
	canonical, e := canonicalResilientGroup(resilientAttrs(1))
	reordered := bytes.Join([][]byte{attr(4, make([]byte, 8)), attr(3, u32(0)), attr(2, u32(12000)), attr(1, []byte{32, 0}), attr(0, nil), attr(0, nil)}, nil)
	other, e2 := canonicalResilientGroup(reordered)
	if e != nil || e2 != nil || !bytes.Equal(canonical, other) {
		t.Fatal("resilient attr order/padding")
	}
	changed := bytes.Replace(resilientObject(1), attr(2, u32(12000)), attr(2, u32(13000)), 1)
	if a.semantic == mustObject(t, changed).semantic {
		t.Fatal("resilient timer drift ignored")
	}
	for _, p := range [][]byte{nil, attr(1, []byte{0, 0}), append(resilientAttrs(1), attr(2, u32(1))...), bytes.Replace(resilientAttrs(0), attr(4, make([]byte, 8)), attr(4, []byte{0}), 1), attr(0, []byte{1})} {
		if _, e := canonicalResilientGroup(p); e != ErrUnavailable {
			t.Fatal("malformed nested resilient group")
		}
	}
}

func TestNextHopMalformedAndBoundsRefused(t *testing.T) {
	bad := [][]byte{nil, make([]byte, 7), make([]byte, maxDatagramBytes+1), objectPayload(0, 1), objectPayload(unix.AF_INET, 0, attr(nhaOIF, u32(2))), objectPayload(255, 1, attr(nhaOIF, u32(2))), objectPayload(unix.AF_INET, 1), objectPayload(unix.AF_INET, 1, attr(nhaOIF, u32(0))), objectPayload(unix.AF_INET, 1, attr(nhaID, u32(1)), attr(nhaOIF, u32(2))), objectGroup(1, objectMember(2, 65536)), objectGroup(1, objectMember(2, 1), objectMember(2, 2)), objectGroup(1, objectMember(0, 1)), objectGroup(1), objectPayload(unix.AF_INET, 1, attr(nhaBlackhole, nil), attr(nhaOIF, u32(2))), objectPayload(unix.AF_INET, 1, attr(nhaFDB, nil), attr(nhaOIF, u32(2))), objectPayload(0, 1, attr(nhaGroup, objectMember(2, 1)), attr(nhaGroupType, []byte{1, 0}), attr(nhaOpFlags, u32(1<<31)))}
	reserved := objectGroup(1, objectMember(2, 1))
	reserved[26] = 1
	bad = append(bad, reserved)
	header := objectPayload(unix.AF_INET, 1, attr(nhaOIF, u32(2)))
	header[3] = 1
	bad = append(bad, header)
	for _, kind := range []uint16{nhaID, nhaOIF, nhaGateway, nhaGroupType, nhaOpFlags, nhaEncapType} {
		bad = append(bad, objectPayload(unix.AF_INET, 1, attr(kind, []byte{0})), objectPayload(unix.AF_INET, 1, attr(kind|0x8000, u32(2))))
	}
	for _, kind := range []uint16{nhaGroups, nhaMaster, nhaResBucket, nhaGroupStats, nhaHWStatsEnable, nhaHWStatsUsed} {
		bad = append(bad, objectPayload(unix.AF_INET, 1, attr(nhaOIF, u32(2)), attr(kind, u32(1))))
	}
	bad = append(bad, objectPayload(0, 1, attr(nhaGroup, objectMember(2, 1)), attr(nhaGroupType, []byte{0, 0}), attr(nhaOpFlags, u32(1))))
	members := [][]byte{}
	for i := range maxNextHops + 1 {
		members = append(members, objectMember(uint32(i+2), 1))
	}
	bad = append(bad, objectGroup(1, members...))
	for i, p := range bad {
		if _, e := parseNextHopObject(p); e != ErrUnavailable {
			t.Fatalf("malformed object %d accepted", i)
		}
	}
	d := dump{seq: 1, port: 9, kind: unix.RTM_NEWNEXTHOP, objects: make([]nextHopObject, MaxNextHopObjects)}
	if d.consume(frame(unix.RTM_NEWNEXTHOP, unix.NLM_F_MULTI, objectPayload(unix.AF_INET, 1, attr(nhaBlackhole, nil)))) != ErrUnavailable {
		t.Fatal("object count unbounded")
	}
	for _, flags := range []uint16{unix.NLM_F_MULTI | unix.NLM_F_DUMP_FILTERED, unix.NLM_F_MULTI | unix.NLM_F_DUMP_INTR, 0} {
		d = dump{seq: 1, port: 9, kind: unix.RTM_NEWNEXTHOP}
		if d.consume(frame(unix.RTM_NEWNEXTHOP, flags, objectPayload(unix.AF_INET, 1, attr(nhaBlackhole, nil)))) != ErrUnavailable {
			t.Fatal("incomplete nexthop dump accepted")
		}
	}
	d = dump{seq: 1, port: 9, kind: unix.RTM_NEWNEXTHOP, objects: []nextHopObject{}}
	if d.consume(frame(unix.NLMSG_DONE, unix.NLM_F_MULTI, u32(0))) != nil || !d.done || d.objects == nil || len(d.objects) != 0 {
		t.Fatal("completed empty nexthop roster")
	}
}

func objectSample(t *testing.T) snapshot {
	s := sample()
	s.objects = []nextHopObject{mustObject(t, objectPayload(unix.AF_INET, 7, attr(nhaOIF, u32(2)))), mustObject(t, objectPayload(unix.AF_INET, 8, attr(nhaBlackhole, nil))), mustObject(t, objectGroup(20, objectMember(7, 257)))}
	r, e := parseRoute(routePayload(unix.AF_INET, 0, attr(routeNextHopID, u32(20))))
	if e != nil || r.objectID != 20 || !r.unresolved {
		t.Fatal("route object reference not retained")
	}
	s.routes = []route{r}
	return s
}

func TestNextHopCompleteRosterReferencesDriftAliasAndPrivacy(t *testing.T) {
	for _, change := range []func(*snapshot){func(s *snapshot) { s.objects = nil }, func(s *snapshot) { s.objects = make([]nextHopObject, MaxNextHopObjects+1) }, func(s *snapshot) { s.objects = append(s.objects, s.objects[0]) }, func(s *snapshot) { s.objects[0].output = 99 }, func(s *snapshot) { s.objects[2].members[0].id = 99 }, func(s *snapshot) { s.objects[2].members[0].id = 20 }, func(s *snapshot) { s.objects[2].members[0].weight = 0 }, func(s *snapshot) { s.objects[2].members[0].weight = 65536 }, func(s *snapshot) { s.objects[2].fdb = true }, func(s *snapshot) { s.routes[0].objectID = 99 }} {
		s := objectSample(t)
		change(&s)
		if normalize(&s) != ErrUnavailable {
			t.Fatal("incomplete object correlation accepted")
		}
	}
	r := readerFixture()
	r.samples = []snapshot{objectSample(t), objectSample(t)}
	slices.Reverse(r.samples[1].objects)
	o, e := observe(context.Background(), r)
	if e != nil {
		t.Fatal(e)
	}
	s, e := o.Summary()
	if e != nil || s.NextHopObjects != 3 || s.UnresolvedNextHopObjects != 0 || s.UnresolvedRoutes != 1 {
		t.Fatal("redacted object/route semantics")
	}
	r.samples[0].objects[2].members[0].weight = 99
	if o.state.objects[2].members[0].weight != 257 {
		t.Fatal("object member aliases provider")
	}
	if _, e := json.Marshal(o); e == nil {
		t.Fatal("serialized object IDs")
	}
	for _, change := range []func(*snapshot){func(s *snapshot) { s.objects[0].semantic[0] ^= 1 }, func(s *snapshot) { s.objects[1].semantic[0] ^= 1 }, func(s *snapshot) { s.objects[2].members[0].weight++ }, func(s *snapshot) { s.objects = s.objects[:2] }} {
		r = readerFixture()
		r.samples = []snapshot{objectSample(t), objectSample(t)}
		change(&r.samples[1])
		if o, e := observe(context.Background(), r); o != nil || e != ErrUnavailable || r.reads != 2 {
			t.Fatal("object drift/partial accepted")
		}
	}
	sample := objectSample(t)
	sample.objects[0].unresolved = true
	if normalize(&sample) != nil || !sample.objects[2].unresolved {
		t.Fatal("leaf uncertainty lost")
	}
}

func TestNextHopBoundedMutationNoPanic(t *testing.T) {
	seed := resilientObject(1)
	rng := rand.New(rand.NewPCG(6105, 20261003))
	for range 5000 {
		p := bytes.Clone(seed)
		for range 1 + rng.IntN(8) {
			p[rng.IntN(len(p))] = byte(rng.IntN(256))
		}
		if _, e := parseNextHopObject(p); e != nil && e != ErrUnavailable {
			t.Fatal("non-redacted nexthop error")
		}
	}
}

func FuzzNextHopObject(f *testing.F) {
	f.Add(objectPayload(unix.AF_INET, 7, attr(nhaOIF, u32(2))))
	f.Add(objectGroup(20, objectMember(7, 257)))
	f.Add(resilientObject(1))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, p []byte) {
		if len(p) > maxDatagramBytes {
			return
		}
		n, e := parseNextHopObject(p)
		if e != nil && e != ErrUnavailable {
			t.Fatal("non-redacted object error")
		}
		if len(n.members) > maxNextHops {
			t.Fatal("unbounded group")
		}
	})
}
