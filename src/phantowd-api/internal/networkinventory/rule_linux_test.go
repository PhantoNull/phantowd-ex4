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

func TestRuleDumpRequestHasFixedIPFamilyAndNoSelectors(t *testing.T) {
	for _, family := range []byte{unix.AF_INET, unix.AF_INET6} {
		m, e := requestMessage(unix.RTM_GETRULE, unix.RTM_NEWRULE, family, 7)
		if e != nil || len(m) != 28 || m[16] != family || binary.NativeEndian.Uint32(m) != 28 || binary.NativeEndian.Uint16(m[4:]) != unix.RTM_GETRULE || binary.NativeEndian.Uint16(m[6:]) != unix.NLM_F_REQUEST|unix.NLM_F_DUMP || binary.NativeEndian.Uint32(m[8:]) != 7 || !bytes.Equal(m[12:16], make([]byte, 4)) || !bytes.Equal(m[17:], make([]byte, 11)) {
			t.Fatal("request escapes declared IPv4/IPv6 rule scope")
		}
	}
	for _, family := range []byte{unix.AF_UNSPEC, 128, 129, 255} {
		if _, e := requestMessage(unix.RTM_GETRULE, unix.RTM_NEWRULE, family, 7); e != ErrUnavailable {
			t.Fatal("undeclared rule family accepted")
		}
	}
	for _, pair := range [][2]uint16{{unix.RTM_GETRULE, unix.RTM_NEWROUTE}, {unix.RTM_GETADDR, unix.RTM_NEWRULE}, {unix.RTM_NEWRULE, unix.RTM_NEWRULE}} {
		if _, e := requestMessage(pair[0], pair[1], unix.AF_INET, 7); e != ErrUnavailable {
			t.Fatal("undeclared/mutating request accepted")
		}
	}
}

func rulePayload(family byte, priority uint32, attrs ...[]byte) []byte {
	b := []byte{family, 0, 0, 0, unix.RT_TABLE_MAIN, 0, 0, unix.FR_ACT_TO_TBL, 0, 0, 0, 0}
	b = append(b, attr(unix.FRA_PRIORITY, u32(priority))...)
	for _, a := range attrs {
		b = append(b, a...)
	}
	return b
}

func TestRuleFieldsCanonicalAttributesAndUnresolvedSemantics(t *testing.T) {
	p := rulePayload(unix.AF_INET, 42, attr(unix.FRA_TABLE, u32(1000)), attr(unix.FRA_SRC, []byte{192, 0, 2, 0}), attr(unix.FRA_DST, []byte{198, 51, 100, 0}), attr(unix.FRA_IIFNAME, []byte("lo\x00")), attr(unix.FRA_OIFNAME, []byte("fixture0\x00")))
	p[1] = 24
	p[2] = 24
	p[3] = 16
	binary.NativeEndian.PutUint32(p[8:], unix.FIB_RULE_INVERT)
	r, e := parseRule(p)
	if e != nil || r.family != unix.AF_INET || r.source.String() != "192.0.2.0/24" || r.destination.String() != "198.51.100.0/24" || r.priority != 42 || r.table != 1000 || r.input != "lo" || r.output != "fixture0" || r.flags != unix.FIB_RULE_INVERT || r.tos != 16 || r.action != unix.FR_ACT_TO_TBL || r.unresolved {
		t.Fatal("rule selectors/header lost")
	}
	for _, a := range [][]byte{attr(unix.FRA_FWMARK, u32(7)), attr(unix.FRA_FWMASK, u32(255)), attr(unix.FRA_TUN_ID, make([]byte, 8)), attr(unix.FRA_SUPPRESS_IFGROUP, u32(1)), attr(unix.FRA_SUPPRESS_PREFIXLEN, u32(24)), attr(unix.FRA_UID_RANGE, append(u32(1000), u32(1001)...)), attr(unix.FRA_SPORT_RANGE, []byte{1, 0, 2, 0}), attr(unix.FRA_DPORT_RANGE, []byte{1, 0, 2, 0}), attr(unix.FRA_L3MDEV, []byte{1}), attr(unix.FRA_IP_PROTO, []byte{6}), attr(ruleDSCP, []byte{12}), attr(ruleFlowLabel, []byte{0, 0, 1, 0}), attr(ruleSourcePortMask, []byte{255, 0}), attr(500|0x8000, []byte{1})} {
		r, e := parseRule(rulePayload(unix.AF_INET, 42, a))
		if e != nil || !r.unresolved {
			t.Fatal("complex or unknown rule semantics hidden")
		}
	}
	a, e := parseRule(rulePayload(unix.AF_INET, 42, attr(unix.FRA_TABLE, u32(1000)), attr(unix.FRA_PROTOCOL, []byte{2})))
	b, e2 := parseRule(append([]byte{unix.AF_INET, 0, 0, 0, unix.RT_TABLE_MAIN, 0, 0, unix.FR_ACT_TO_TBL, 0, 0, 0, 0}, append(append(attr(unix.FRA_PROTOCOL, []byte{2}), attr(unix.FRA_TABLE, u32(1000))...), attr(unix.FRA_PRIORITY, u32(42))...)...))
	if e != nil || e2 != nil || a.semantic != b.semantic || a.unresolved {
		t.Fatal("attribute order changes rule semantics")
	}
	ip6 := netip.MustParseAddr("2001:db8::").As16()
	p = rulePayload(unix.AF_INET6, 42, attr(unix.FRA_SRC, ip6[:]))
	p[2] = 64
	if r, e := parseRule(p); e != nil || r.source.String() != "2001:db8::/64" {
		t.Fatal("IPv6 rule prefix lost")
	}
	p = rulePayload(unix.AF_INET, 42, attr(unix.FRA_GOTO, u32(100)))
	p[7] = unix.FR_ACT_GOTO
	if r, e := parseRule(p); e != nil || r.target != 100 || !r.unresolved {
		t.Fatal("unresolved goto hidden")
	}
}

func TestRuleOrderingMultiplicityCorrelationAndDrift(t *testing.T) {
	a, _ := parseRule(rulePayload(unix.AF_INET, 42, attr(unix.FRA_TABLE, u32(1000))))
	b, _ := parseRule(rulePayload(unix.AF_INET, 42, attr(unix.FRA_TABLE, u32(1001))))
	c, _ := parseRule(rulePayload(unix.AF_INET6, 1))
	r := readerFixture()
	r.samples[0].rules = []rule{a, b, c}
	r.samples[1].rules = []rule{c, a, b}
	o, e := observe(context.Background(), r)
	if e != nil {
		t.Fatal("cross-family order refused")
	}
	s, e := o.Summary()
	if e != nil || s.Rules != 3 || s.UnresolvedRules != 0 {
		t.Fatal("rule counts")
	}
	r.samples[0].rules[0].table = 999
	if o.state.rules[0].table != 1000 {
		t.Fatal("rule result aliases provider")
	}
	r = readerFixture()
	r.samples[0].rules = []rule{a, b}
	r.samples[1].rules = []rule{b, a}
	if o, e := observe(context.Background(), r); o != nil || e != ErrUnavailable {
		t.Fatal("same-priority reorder hidden")
	}
	r = readerFixture()
	r.samples[0].rules = []rule{a, a}
	r.samples[1].rules = []rule{a, a}
	o, e = observe(context.Background(), r)
	if e != nil {
		t.Fatal("duplicate multiplicity refused")
	}
	s, _ = o.Summary()
	if s.Rules != 2 {
		t.Fatal("duplicates deduplicated")
	}
	for _, change := range []func(*snapshot){func(s *snapshot) { s.rules = nil }, func(s *snapshot) { s.rules = make([]rule, MaxRules+1) }, func(s *snapshot) { s.rules = []rule{b, a}; s.rules[0].priority = 43 }, func(s *snapshot) { s.rules[0].input = "missing" }, func(s *snapshot) { s.rules[0].output = "missing" }, func(s *snapshot) { s.rules[0].source = netip.Prefix{} }} {
		s := sample()
		s.rules = []rule{a}
		change(&s)
		if normalize(&s) != ErrUnavailable {
			t.Fatal("incomplete/malformed rule set admitted")
		}
	}
	p := rulePayload(unix.AF_INET, 42, attr(unix.FRA_IIFNAME, []byte("missing\x00")))
	binary.NativeEndian.PutUint32(p[8:], unix.FIB_RULE_IIF_DETACHED)
	detached, e := parseRule(p)
	if e != nil {
		t.Fatal(e)
	}
	snp := sample()
	snp.rules = []rule{detached}
	if normalize(&snp) != nil || !snp.rules[0].unresolved {
		t.Fatal("valid detached rule not observed as unresolved")
	}
	for _, change := range []func(*rule){func(r *rule) { r.semantic[0] ^= 1 }, func(r *rule) { r.flags++ }, func(r *rule) { r.table++ }, func(r *rule) { r.action = unix.FR_ACT_BLACKHOLE }} {
		r := readerFixture()
		r.samples[0].rules = []rule{a}
		r.samples[1].rules = []rule{a}
		change(&r.samples[1].rules[0])
		if o, e := observe(context.Background(), r); o != nil || e != ErrUnavailable || r.reads != 2 {
			t.Fatal("rule drift retried/hidden")
		}
	}
}

func TestMalformedRuleWireAndDumpRefused(t *testing.T) {
	bad := [][]byte{nil, make([]byte, 11), rulePayload(128, 1)}
	for _, offset := range []int{1, 2, 5, 6} {
		p := rulePayload(unix.AF_INET, 1)
		p[offset] = 255
		bad = append(bad, p)
	}
	for _, kind := range []uint16{unix.FRA_DST, unix.FRA_SRC, unix.FRA_IIFNAME, unix.FRA_OIFNAME, unix.FRA_TABLE, unix.FRA_GOTO, unix.FRA_FWMARK, unix.FRA_FWMASK, unix.FRA_TUN_ID, unix.FRA_SUPPRESS_PREFIXLEN, unix.FRA_UID_RANGE, unix.FRA_SPORT_RANGE, ruleFlowLabel, ruleSourcePortMask} {
		bad = append(bad, rulePayload(unix.AF_INET, 1, attr(kind, []byte{1})))
	}
	for _, a := range [][]byte{attr(unix.FRA_PRIORITY, u32(1)), attr(unix.FRA_IIFNAME, []byte("bad/path\x00")), attr(unix.FRA_IIFNAME, []byte("bad\x00extra\x00")), attr(unix.FRA_TABLE|0x8000, u32(1)), attr(unix.FRA_UID_RANGE, append(u32(2), u32(1)...)), attr(unix.FRA_SPORT_RANGE, []byte{2, 0, 1, 0}), attr(unix.FRA_L3MDEV, []byte{2}), attr(ruleDSCP, []byte{64}), attr(ruleDSCPMask, []byte{64}), attr(ruleFlowLabel, []byte{255, 0, 0, 0}), attr(unix.FRA_SUPPRESS_PREFIXLEN, u32(33))} {
		bad = append(bad, rulePayload(unix.AF_INET, 1, a))
	}
	for i, p := range bad {
		if _, e := parseRule(p); e != ErrUnavailable {
			t.Fatalf("malformed rule %d admitted", i)
		}
	}
	p := rulePayload(unix.AF_INET, 1)
	d := dump{seq: 1, port: 9, kind: unix.RTM_NEWRULE, family: unix.AF_INET}
	if d.consume(frame(unix.RTM_NEWRULE, unix.NLM_F_MULTI, p)) != nil || len(d.rules) != 1 {
		t.Fatal("rule dump refused")
	}
	d = dump{seq: 1, port: 9, kind: unix.RTM_NEWRULE, family: unix.AF_INET6}
	if d.consume(frame(unix.RTM_NEWRULE, unix.NLM_F_MULTI, p)) != ErrUnavailable {
		t.Fatal("wrong response family accepted")
	}
	for _, flags := range []uint16{unix.NLM_F_MULTI | unix.NLM_F_DUMP_FILTERED, unix.NLM_F_MULTI | unix.NLM_F_DUMP_INTR} {
		d := dump{seq: 1, port: 9, kind: unix.RTM_NEWRULE, configuredRoutes: true, family: unix.AF_INET}
		if d.consume(frame(unix.RTM_NEWRULE, flags, p)) != ErrUnavailable {
			t.Fatal("filtered/interrupted rules accepted")
		}
	}
	d = dump{seq: 1, port: 9, kind: unix.RTM_NEWRULE, rules: make([]rule, MaxRules), family: unix.AF_INET}
	if d.consume(frame(unix.RTM_NEWRULE, unix.NLM_F_MULTI, p)) != ErrUnavailable {
		t.Fatal("rule count unbounded")
	}
}

func TestRuleBoundedMutationsAndPadding(t *testing.T) {
	seed := rulePayload(unix.AF_INET, 42, attr(unix.FRA_TABLE, u32(1000)))
	a, e := parseRule(seed)
	b, e2 := parseRule(append(slices.Clone(seed), attr(unix.FRA_PAD, nil)...))
	if e != nil || e2 != nil || a.semantic != b.semantic {
		t.Fatal("padding changes rule semantics")
	}
	rng := rand.New(rand.NewPCG(6104, 20261003))
	for range 5000 {
		p := bytes.Clone(seed)
		for range 1 + rng.IntN(8) {
			p[rng.IntN(len(p))] = byte(rng.IntN(256))
		}
		if _, e := parseRule(p); e != nil && e != ErrUnavailable {
			t.Fatal("unredacted error")
		}
	}
}

func FuzzRule(f *testing.F) {
	f.Add(rulePayload(unix.AF_INET, 42, attr(unix.FRA_TABLE, u32(1000))))
	f.Add(rulePayload(unix.AF_INET6, 42, attr(unix.FRA_IIFNAME, []byte("lo\x00"))))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, p []byte) {
		if len(p) > maxDatagramBytes {
			return
		}
		if _, e := parseRule(p); e != nil && e != ErrUnavailable {
			t.Fatal("unredacted error")
		}
	})
}
