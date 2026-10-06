// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package networkinventory

import (
	"bytes"
	"context"
	"encoding/binary"
	"math/rand/v2"
	"net/netip"
	"slices"
	"testing"

	"golang.org/x/sys/unix"
)

func routePayload(family byte, bits byte, attrs ...[]byte) []byte {
	b := []byte{family, bits, 0, 0, unix.RT_TABLE_MAIN, unix.RTPROT_STATIC, unix.RT_SCOPE_UNIVERSE, unix.RTN_UNICAST, 0, 0, 0, 0}
	for _, a := range attrs {
		b = append(b, a...)
	}
	return b
}

func TestConfiguredRouteDumpAllowsOnlyItsDeclaredFilter(t *testing.T) {
	p := routePayload(unix.AF_INET, 0, attr(unix.RTA_OIF, u32(1)))
	filtered := frame(unix.RTM_NEWROUTE, unix.NLM_F_MULTI|unix.NLM_F_DUMP_FILTERED, p)
	d := dump{seq: 1, port: 9, kind: unix.RTM_NEWROUTE, configuredRoutes: true}
	if d.consume(filtered) != nil || len(d.routes) != 1 {
		t.Fatal("fixed strict FIB-only dump refused")
	}
	if d.consume(frame(unix.NLMSG_DONE, unix.NLM_F_MULTI|unix.NLM_F_DUMP_FILTERED, u32(0))) != nil || !d.done {
		t.Fatal("FIB-only completion refused")
	}
	for _, kind := range []uint16{unix.RTM_NEWLINK, unix.RTM_NEWADDR, unix.RTM_NEWROUTE} {
		d := dump{seq: 1, port: 9, kind: kind}
		if d.consume(filtered) != ErrUnavailable {
			t.Fatal("undeclared filtered dump accepted")
		}
	}
	for _, flags := range []uint16{unix.NLM_F_MULTI | unix.NLM_F_DUMP_INTR, unix.NLM_F_MULTI | unix.NLM_F_DUMP_FILTERED | unix.NLM_F_DUMP_INTR, unix.NLM_F_MULTI | unix.NLM_F_ACK} {
		d := dump{seq: 1, port: 9, kind: unix.RTM_NEWROUTE, configuredRoutes: true}
		if d.consume(frame(unix.RTM_NEWROUTE, flags, p)) != ErrUnavailable {
			t.Fatal("uncertain route dump accepted")
		}
	}
}

func TestRouteFieldsFamiliesTablesAndTerminalEntries(t *testing.T) {
	p := routePayload(unix.AF_INET, 24,
		attr(unix.RTA_DST, []byte{192, 0, 2, 0}), attr(unix.RTA_SRC, []byte{198, 51, 100, 0}),
		attr(unix.RTA_OIF, u32(2)), attr(unix.RTA_IIF, u32(1)), attr(unix.RTA_TABLE, u32(1000)),
		attr(unix.RTA_PRIORITY, u32(42)), attr(unix.RTA_GATEWAY, []byte{192, 0, 2, 1}), attr(unix.RTA_PREFSRC, []byte{192, 0, 2, 10}))
	p[2] = 24
	p[3] = 16
	p[6] = unix.RT_SCOPE_LINK
	binary.NativeEndian.PutUint32(p[8:], 4)
	r, e := parseRoute(p)
	if e != nil || r.destination.String() != "192.0.2.0/24" || r.source.String() != "198.51.100.0/24" || r.table != 1000 || r.metric != 42 || r.input != 1 || r.output != 2 || r.flags != 4 || r.protocol != unix.RTPROT_STATIC || r.scope != unix.RT_SCOPE_LINK || r.kind != unix.RTN_UNICAST || r.tos != 16 || r.gateway.String() != "192.0.2.1" || r.preferred.String() != "192.0.2.10" || r.unresolved {
		t.Fatal("route fields lost")
	}
	for _, family := range []byte{unix.AF_INET, unix.AF_INET6} {
		for _, kind := range []byte{unix.RTN_UNICAST, unix.RTN_LOCAL, unix.RTN_BROADCAST, unix.RTN_BLACKHOLE, unix.RTN_UNREACHABLE, unix.RTN_PROHIBIT, unix.RTN_THROW} {
			p := routePayload(family, 0)
			p[7] = kind
			r, e := parseRoute(p)
			if e != nil || r.kind != kind || r.destination.Bits() != 0 || r.source.Bits() != 0 {
				t.Fatal("default or terminal route lost")
			}
		}
	}
	addr := netip.MustParseAddr("2001:db8::").As16()
	via := append([]byte{0, 0}, []byte{192, 0, 2, 1}...)
	binary.NativeEndian.PutUint16(via, unix.AF_INET)
	r, e = parseRoute(routePayload(unix.AF_INET6, 64, attr(unix.RTA_DST, addr[:]), attr(unix.RTA_VIA, via)))
	if e != nil || r.destination.String() != "2001:db8::/64" || r.via.String() != "192.0.2.1" {
		t.Fatal("IPv6 prefix/cross-family via lost")
	}
}

func nh(index uint32, flags, hops byte, attrs ...[]byte) []byte {
	b := make([]byte, 8)
	b[2] = flags
	b[3] = hops
	binary.NativeEndian.PutUint32(b[4:], index)
	for _, a := range attrs {
		b = append(b, a...)
	}
	binary.NativeEndian.PutUint16(b, uint16(len(b)))
	return b
}

func TestRouteCanonicalOrderingMultipathAndVolatileCache(t *testing.T) {
	first := nh(1, unix.RTNH_F_ONLINK, 0, attr(unix.RTA_GATEWAY, []byte{192, 0, 2, 1}))
	second := nh(2, unix.RTNH_F_LINKDOWN, 2, attr(unix.RTA_GATEWAY, []byte{192, 0, 2, 2}))
	r, e := parseRoute(routePayload(unix.AF_INET, 0, attr(unix.RTA_PRIORITY, u32(10)), attr(unix.RTA_MULTIPATH, append(bytes.Clone(first), second...))))
	other, e2 := parseRoute(routePayload(unix.AF_INET, 0, attr(unix.RTA_MULTIPATH, append(bytes.Clone(first), second...)), attr(unix.RTA_PRIORITY, u32(10))))
	if e != nil || e2 != nil || r.semantic != other.semantic || !slices.Equal(r.next, other.next) || len(r.next) != 2 || r.unresolved {
		t.Fatal("ECMP ordering/fields lost")
	}
	for _, n := range r.next {
		if n.index == 2 && (n.hops != 2 || n.flags != unix.RTNH_F_LINKDOWN || n.gateway.String() != "192.0.2.2") {
			t.Fatal("member weight/state lost")
		}
	}
	cache := make([]byte, 32)
	a, e := parseRoute(routePayload(unix.AF_INET, 0, attr(unix.RTA_CACHEINFO, cache), attr(unix.RTA_EXPIRES, u32(100))))
	cache[0] = 1
	cache[4] = 2
	cache[8] = 3
	cache[16] = 4
	cache[20] = 5
	cache[24] = 6
	cache[28] = 7
	b, e2 := parseRoute(routePayload(unix.AF_INET, 0, attr(unix.RTA_EXPIRES, u32(90)), attr(unix.RTA_CACHEINFO, cache)))
	if e != nil || e2 != nil || a.semantic != b.semantic {
		t.Fatal("volatile cache causes semantic drift")
	}
	cache[12] = 1
	c, e := parseRoute(routePayload(unix.AF_INET, 0, attr(unix.RTA_CACHEINFO, cache), attr(unix.RTA_EXPIRES, u32(90))))
	if e != nil || a.semantic == c.semantic {
		t.Fatal("cache error discarded")
	}
	second[3]++
	c, e = parseRoute(routePayload(unix.AF_INET, 0, attr(unix.RTA_PRIORITY, u32(10)), attr(unix.RTA_MULTIPATH, append(bytes.Clone(first), second...))))
	if e != nil || c.semantic == r.semantic {
		t.Fatal("ECMP semantic drift discarded")
	}
}

func TestInlineNextHopOrderChangesObservedRouteSemantics(t *testing.T) {
	first := nh(1, 0, 0, attr(unix.RTA_GATEWAY, []byte{192, 0, 2, 1}))
	second := nh(2, 0, 0, attr(unix.RTA_GATEWAY, []byte{192, 0, 2, 2}))
	a, ea := parseRoute(routePayload(unix.AF_INET, 0, attr(unix.RTA_MULTIPATH, append(bytes.Clone(first), second...))))
	b, eb := parseRoute(routePayload(unix.AF_INET, 0, attr(unix.RTA_MULTIPATH, append(bytes.Clone(second), first...))))
	if ea != nil || eb != nil {
		t.Fatal("valid multipath framing")
	}
	if a.semantic == b.semantic || slices.Equal(a.next, b.next) || a.next[0].index != 1 || b.next[0].index != 2 {
		t.Fatal("ordered inline ECMP changes hidden by normalization")
	}
	r := readerFixture()
	r.samples[0].routes = []route{a}
	r.samples[1].routes = []route{b}
	if got, e := observe(context.Background(), r); got != nil || e != ErrUnavailable {
		t.Fatal("ECMP reordering accepted as stable observation")
	}
	duplicate := append(append(bytes.Clone(first), second...), first...)
	if _, e := parseRoute(routePayload(unix.AF_INET, 0, attr(unix.RTA_MULTIPATH, duplicate))); e != ErrUnavailable {
		t.Fatal("non-adjacent duplicate member accepted")
	}
}

func TestRouteUnknownAndReferencedSemanticsRemainUnresolved(t *testing.T) {
	for _, a := range [][]byte{attr(routeNextHopID, u32(7)), attr(500|0x8000, []byte{1, 2}), attr(unix.RTA_METRICS, attr(2, u32(1500))), attr(unix.RTA_ENCAP, []byte{1})} {
		r, e := parseRoute(routePayload(unix.AF_INET, 0, a))
		if e != nil || !r.unresolved {
			t.Fatal("unresolved semantics discarded")
		}
		b := bytes.Clone(a)
		b[int(binary.NativeEndian.Uint16(b))-1] ^= 1
		r2, e := parseRoute(routePayload(unix.AF_INET, 0, b))
		if e != nil || r.semantic == r2.semantic {
			t.Fatal("unknown semantic drift discarded")
		}
	}
	a, e := parseRoute(routePayload(unix.AF_INET, 0, attr(unix.RTA_METRICS, append(attr(2, u32(1500)), attr(3, u32(10))...))))
	b, e2 := parseRoute(routePayload(unix.AF_INET, 0, attr(unix.RTA_METRICS, append(attr(3, u32(10)), attr(2, u32(1500))...))))
	if e != nil || e2 != nil || a.semantic != b.semantic {
		t.Fatal("metric order unstable")
	}
	r, e := parseRoute(routePayload(unix.AF_INET, 0, attr(unix.RTA_MULTIPATH, nh(1, 0, 0, attr(500, []byte{1})))))
	if e != nil || !r.unresolved || !r.next[0].unresolved {
		t.Fatal("unknown member semantics discarded")
	}
}

func TestRouteMalformedAndBoundedInputsRefused(t *testing.T) {
	bad := [][]byte{nil, make([]byte, 11), routePayload(unix.AF_UNSPEC, 0), routePayload(unix.AF_INET, 33), routePayload(unix.AF_INET6, 129), routePayload(unix.AF_INET, 24), routePayload(unix.AF_INET, 24, attr(unix.RTA_DST, []byte{192, 0, 2, 1})), routePayload(unix.AF_INET, 0, attr(unix.RTA_DST, []byte{1})), routePayload(unix.AF_INET, 0, attr(unix.RTA_SRC, []byte{}))}
	for _, kind := range []uint16{unix.RTA_IIF, unix.RTA_OIF, unix.RTA_GATEWAY, unix.RTA_PREFSRC, unix.RTA_PRIORITY, unix.RTA_TABLE, unix.RTA_CACHEINFO, unix.RTA_EXPIRES, unix.RTA_VIA, routeNextHopID} {
		bad = append(bad, routePayload(unix.AF_INET, 0, attr(kind, []byte{1})))
	}
	for _, kind := range []uint16{unix.RTA_IIF, unix.RTA_OIF, routeNextHopID} {
		bad = append(bad, routePayload(unix.AF_INET, 0, attr(kind, u32(0))))
	}
	bad = append(bad, routePayload(unix.AF_INET, 0, attr(unix.RTA_OIF, u32(0xffffffff))), routePayload(unix.AF_INET, 0, attr(unix.RTA_OIF|0x8000, u32(1))), routePayload(unix.AF_INET, 0, attr(unix.RTA_PREF, []byte{1, 2})), routePayload(unix.AF_INET, 0, attr(unix.RTA_VIA, []byte{99, 0, 1, 2, 3, 4})))
	for _, a := range [][]byte{attr(unix.RTA_OIF, u32(1)), attr(500, []byte{}), attr(500|0x8000, []byte{1})} {
		bad = append(bad, routePayload(unix.AF_INET, 0, append(bytes.Clone(a), a...)))
	}
	bad = append(bad, routePayload(unix.AF_INET, 0, attr(unix.RTA_METRICS, append(attr(2, u32(1)), attr(2, u32(2))...))), routePayload(unix.AF_INET, 0, attr(unix.RTA_METRICS, []byte{1})))
	for _, mp := range [][]byte{nil, {1}, {0, 0, 0, 0, 0, 0, 0, 0}, nh(0, 0, 0), nh(0xffffffff, 0, 0), nh(1, 0, 0, attr(unix.RTA_GATEWAY, []byte{1})), append(nh(1, 0, 0), nh(1, 0, 0)...), nh(1, 0, 0, attr(unix.RTA_VIA|0x8000, []byte{2, 0, 1, 2, 3, 4}))} {
		bad = append(bad, routePayload(unix.AF_INET, 0, attr(unix.RTA_MULTIPATH, mp)))
	}
	mp := []byte{}
	for i := 0; i < maxNextHops+1; i++ {
		mp = append(mp, nh(uint32(i+1), 0, 0)...)
	}
	bad = append(bad, routePayload(unix.AF_INET, 0, attr(unix.RTA_MULTIPATH, mp)))
	tooMany := []byte{}
	for i := 0; i < maxRouteAttributes+1; i++ {
		tooMany = append(tooMany, attr(uint16(i+500), []byte{1})...)
	}
	bad = append(bad, routePayload(unix.AF_INET, 0, tooMany))
	for i, p := range bad {
		if _, e := parseRoute(p); e != ErrUnavailable {
			t.Fatalf("accepted malformed route %d", i)
		}
	}
	d := dump{seq: 1, port: 9, kind: unix.RTM_NEWROUTE, routes: make([]route, MaxRoutes)}
	if d.consume(frame(unix.RTM_NEWROUTE, unix.NLM_F_MULTI, routePayload(unix.AF_INET, 0))) != ErrUnavailable {
		t.Fatal("route count unbounded")
	}
}

func TestRouteSetCorrelationDriftPrivacyAndProviderOwnership(t *testing.T) {
	r, e := parseRoute(routePayload(unix.AF_INET, 0, attr(unix.RTA_OIF, u32(2)), attr(unix.RTA_MULTIPATH, nh(1, 0, 0))))
	if e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*snapshot){func(s *snapshot) { s.routes = nil }, func(s *snapshot) { s.routes = make([]route, MaxRoutes+1) }, func(s *snapshot) { s.routes[0].output = 99 }, func(s *snapshot) { s.routes[0].input = 99 }, func(s *snapshot) { s.routes[0].next[0].index = 99 }, func(s *snapshot) { s.routes = append(s.routes, s.routes[0]) }} {
		s := sample()
		s.routes = []route{r}
		s.routes[0].next = slices.Clone(r.next)
		change(&s)
		if normalize(&s) != ErrUnavailable {
			t.Fatal("incomplete route set accepted")
		}
	}
	reader := readerFixture()
	reader.samples[0].routes = []route{r}
	reader.samples[1].routes = []route{r}
	reader.samples[0].routes[0].next = slices.Clone(r.next)
	o, e := observe(context.Background(), reader)
	if e != nil {
		t.Fatal(e)
	}
	s, e := o.Summary()
	if e != nil || s.Routes != 1 || s.UnresolvedRoutes != 0 {
		t.Fatal("redacted route counts")
	}
	reader.samples[0].routes[0].next[0].index = 99
	if o.state.routes[0].next[0].index != 1 {
		t.Fatal("member aliases provider")
	}
	reader = readerFixture()
	reader.samples[0].routes = []route{r}
	reader.samples[1].routes = []route{r}
	reader.samples[1].routes[0].semantic[0] ^= 1
	if o, e := observe(context.Background(), reader); o != nil || e != ErrUnavailable || reader.reads != 2 {
		t.Fatal("route drift retry/partial")
	}
	reader = readerFixture()
	r.unresolved = true
	reader.samples[0].routes = []route{r}
	reader.samples[1].routes = []route{r}
	o, e = observe(context.Background(), reader)
	if e != nil {
		t.Fatal(e)
	}
	s, e = o.Summary()
	if e != nil || s.UnresolvedRoutes != 1 {
		t.Fatal("unknown semantics hidden")
	}
}

func TestRouteBoundedMutationNoPanic(t *testing.T) {
	seed := routePayload(unix.AF_INET, 0, attr(unix.RTA_MULTIPATH, nh(1, 0, 0, attr(unix.RTA_GATEWAY, []byte{192, 0, 2, 1}))))
	rng := rand.New(rand.NewPCG(6103, 20261003))
	for range 5000 {
		p := bytes.Clone(seed)
		for range 1 + rng.IntN(8) {
			p[rng.IntN(len(p))] = byte(rng.IntN(256))
		}
		if _, e := parseRoute(p); e != nil && e != ErrUnavailable {
			t.Fatal("non-redacted error")
		}
	}
}

func FuzzRoute(f *testing.F) {
	f.Add(routePayload(unix.AF_INET, 0, attr(unix.RTA_OIF, u32(1))))
	f.Add(routePayload(unix.AF_INET6, 0, attr(unix.RTA_MULTIPATH, nh(1, 0, 0))))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, p []byte) {
		if len(p) > maxDatagramBytes {
			return
		}
		r, e := parseRoute(p)
		if e != nil && e != ErrUnavailable {
			t.Fatal("non-redacted error")
		}
		if len(r.next) > maxNextHops {
			t.Fatal("unbounded route")
		}
	})
}
