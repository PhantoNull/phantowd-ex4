// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package networkpolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math/rand/v2"
	"reflect"
	"strings"
	"testing"
)

func disabled() Family { return Family{Mode: "disabled", Addresses: []string{}} }

func fixture() Policy {
	return Policy{Format: Format, SchemaVersion: 1, Revision: 1, Hostname: "nas-test",
		Interfaces: []Interface{
			{Slot: "lan-1", IPv4: Family{Mode: "static", Addresses: []string{"192.0.2.10/16"},
				DefaultRoute: true, Gateway: "192.0.2.1", Metric: 100},
				IPv6: Family{Mode: "static", Addresses: []string{"2001:db8:1::10/64"},
					DefaultRoute: true, Gateway: "fe80::1", Metric: 100}},
			{Slot: "lan-2", IPv4: disabled(), IPv6: disabled()},
		}, Routes: []Route{{Slot: "lan-1", Destination: "198.51.100.0/24", Gateway: "192.0.2.2", Metric: 200}},
		DNS: DNS{Mode: "manual", Servers: []string{"192.0.2.53", "2001:db8:1::53"}, SearchDomains: []string{"test.invalid"}},
	}
}

func TestPositivePoliciesAndRoundTrip(t *testing.T) {
	cases := map[string]func(*Policy){
		"local DNS":              func(p *Policy) { p.DNS.Servers = []string{"127.0.0.1", "::1"} },
		"global IPv6 gateway":    func(p *Policy) { p.Interfaces[0].IPv6.Gateway = "2001:db8:1::1" },
		"bounded maximum metric": func(p *Policy) { p.Interfaces[0].IPv4.Metric = 65535 },
		"dual stack /16":         func(*Policy) {},
		"aliases same subnet": func(p *Policy) {
			p.Interfaces[0].IPv4.Addresses = append(p.Interfaces[0].IPv4.Addresses, "192.0.2.11/16")
		},
		"dhcp and automatic IPv6": func(p *Policy) {
			p.Interfaces[0].IPv4 = Family{Mode: "dhcp", Addresses: []string{}, DefaultRoute: true, Metric: 100}
			p.Interfaces[0].IPv6 = Family{Mode: "auto", Addresses: []string{}, DefaultRoute: true, Metric: 100}
			p.Routes = []Route{}
			p.DNS = DNS{Mode: "automatic", Source: "lan-1", Servers: []string{}, SearchDomains: []string{}}
		},
		"IPv4 /31 endpoints": func(p *Policy) {
			p.Interfaces[0].IPv4.Addresses = []string{"192.0.2.10/31"}
			p.Interfaces[0].IPv4.Gateway = "192.0.2.11"
			p.Routes = []Route{}
		},
		"host routes": func(p *Policy) {
			p.Interfaces[0].IPv4 = Family{Mode: "static", Addresses: []string{"192.0.2.10/32"}}
			p.Interfaces[0].IPv6 = Family{Mode: "static", Addresses: []string{"fd01::10/128"}}
			p.Routes = []Route{}
		},
		"independent ports and route priorities": func(p *Policy) {
			p.Interfaces[1].IPv4 = Family{Mode: "static", Addresses: []string{"198.51.100.10/24"}, DefaultRoute: true, Gateway: "198.51.100.1", Metric: 200}
			p.Interfaces[1].IPv6 = Family{Mode: "static", Addresses: []string{"fd01::10/64"}, DefaultRoute: true, Gateway: "fe80::1", Metric: 200}
			p.Routes = append(p.Routes, Route{Slot: "lan-2", Destination: "203.0.113.0/24", Gateway: "198.51.100.1", Metric: 300},
				Route{Slot: "lan-2", Destination: "2001:db8:2::/64", Gateway: "fe80::2", Metric: 300})
		},
		"slot order independent": func(p *Policy) { p.Interfaces[0], p.Interfaces[1] = p.Interfaces[1], p.Interfaces[0] },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			p := fixture()
			change(&p)
			data, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			if err := p.Validate(); err != nil {
				t.Fatal(err)
			}
			got, err := Decode(bytes.NewReader(data))
			if err != nil || !reflect.DeepEqual(got, p) {
				t.Fatalf("round trip failed: %v", err)
			}
			after, _ := json.Marshal(p)
			if !bytes.Equal(data, after) {
				t.Fatal("validation mutated input")
			}
		})
	}
}

func TestInvalidPolicies(t *testing.T) {
	cases := map[string]func(*Policy){
		"oversize address":     func(p *Policy) { p.Interfaces[0].IPv4.Addresses = []string{strings.Repeat("a", 65)} },
		"oversize destination": func(p *Policy) { p.Routes[0].Destination = strings.Repeat("a", 65) },
		"oversize gateway":     func(p *Policy) { p.Interfaces[0].IPv4.Gateway = strings.Repeat("a", 65) },
		"format":               func(p *Policy) { p.Format = "other" },
		"schema":               func(p *Policy) { p.SchemaVersion = 2 },
		"revision":             func(p *Policy) { p.Revision = 0 },
		"hostname injection":   func(p *Policy) { p.Hostname = "nas\ncommand" },
		"hostname fqdn":        func(p *Policy) { p.Hostname = "nas.invalid" },
		"hostname uppercase":   func(p *Policy) { p.Hostname = "NAS" },
		"hostname hyphen":      func(p *Policy) { p.Hostname = "-nas" },
		"hostname long":        func(p *Policy) { p.Hostname = strings.Repeat("a", 64) },
		"missing slot":         func(p *Policy) { p.Interfaces = p.Interfaces[:1] },
		"extra slot":           func(p *Policy) { p.Interfaces = append(p.Interfaces, p.Interfaces[0]) },
		"kernel name":          func(p *Policy) { p.Interfaces[0].Slot = "eth0" },
		"duplicate slot":       func(p *Policy) { p.Interfaces[1].Slot = "lan-1" },
		"all disabled":         func(p *Policy) { p.Interfaces[0].IPv4 = disabled(); p.Interfaces[0].IPv6 = disabled() },
		"unknown mode":         func(p *Policy) { p.Interfaces[0].IPv4.Mode = "automatic" },
		"wrong v4 mode":        func(p *Policy) { p.Interfaces[0].IPv4.Mode = "auto" },
		"wrong v6 mode":        func(p *Policy) { p.Interfaces[0].IPv6.Mode = "dhcp" },
		"absent address list":  func(p *Policy) { p.Interfaces[1].IPv4.Addresses = nil },
		"empty static":         func(p *Policy) { p.Interfaces[0].IPv4.Addresses = []string{} },
		"too many aliases": func(p *Policy) {
			p.Interfaces[0].IPv4.Addresses = []string{"192.0.2.10/16", "192.0.2.11/16", "192.0.2.12/16", "192.0.2.13/16", "192.0.2.14/16"}
		},
		"dhcp addresses":      func(p *Policy) { p.Interfaces[0].IPv4.Mode = "dhcp"; p.Interfaces[0].IPv4.Gateway = "" },
		"disabled address":    func(p *Policy) { p.Interfaces[1].IPv4.Addresses = []string{"203.0.113.5/24"} },
		"disabled default":    func(p *Policy) { p.Interfaces[1].IPv4.DefaultRoute = true; p.Interfaces[1].IPv4.Metric = 10 },
		"missing metric":      func(p *Policy) { p.Interfaces[0].IPv4.Metric = 0 },
		"unused metric":       func(p *Policy) { p.Interfaces[1].IPv4.Metric = 5 },
		"missing gateway":     func(p *Policy) { p.Interfaces[0].IPv4.Gateway = "" },
		"dhcp manual gateway": func(p *Policy) { p.Interfaces[0].IPv4.Mode = "dhcp"; p.Interfaces[0].IPv4.Addresses = []string{} },
		"duplicate alias": func(p *Policy) {
			p.Interfaces[0].IPv4.Addresses = append(p.Interfaces[0].IPv4.Addresses, "192.0.2.10/24")
		},
		"overlapping slots": func(p *Policy) { p.Interfaces[1].IPv4 = Family{Mode: "static", Addresses: []string{"192.0.3.10/24"}} },
		"overlapping IPv6": func(p *Policy) {
			p.Interfaces[1].IPv6 = Family{Mode: "static", Addresses: []string{"2001:db8:1::11/80"}}
		},
		"equal default priorities": func(p *Policy) {
			p.Interfaces[1].IPv4 = Family{Mode: "dhcp", Addresses: []string{}, DefaultRoute: true, Metric: 100}
		},
		"off link gateway": func(p *Policy) { p.Interfaces[0].IPv4.Gateway = "198.51.100.1" },
		"self gateway":     func(p *Policy) { p.Interfaces[0].IPv4.Gateway = "192.0.2.10" },
		"other slot gateway": func(p *Policy) {
			p.Interfaces[1].IPv4 = Family{Mode: "static", Addresses: []string{"198.51.100.10/24"}}
			p.Interfaces[0].IPv4.Gateway = "198.51.100.10"
		},
		"broadcast gateway":            func(p *Policy) { p.Interfaces[0].IPv4.Gateway = "192.0.255.255" },
		"unscoped manual IPv6 gateway": func(p *Policy) { p.Interfaces[0].IPv6.Gateway = "fe80::1%eth0" },
		"off link IPv6 gateway":        func(p *Policy) { p.Interfaces[0].IPv6.Gateway = "2001:db8:2::1" },
		"missing routes":               func(p *Policy) { p.Routes = nil },
		"excess routes": func(p *Policy) {
			for len(p.Routes) <= MaxRoutes {
				p.Routes = append(p.Routes, p.Routes[0])
			}
		},
		"route host bits":            func(p *Policy) { p.Routes[0].Destination = "198.51.100.1/24" },
		"route default":              func(p *Policy) { p.Routes[0].Destination = "0.0.0.0/0" },
		"route missing metric":       func(p *Policy) { p.Routes[0].Metric = 0 },
		"route wrong slot":           func(p *Policy) { p.Routes[0].Slot = "eth0" },
		"route disabled family":      func(p *Policy) { p.Routes[0].Slot = "lan-2" },
		"route wrong gateway family": func(p *Policy) { p.Routes[0].Gateway = "fe80::1" },
		"route ties":                 func(p *Policy) { p.Routes = append(p.Routes, p.Routes[0]) },
		"DNS missing lists":          func(p *Policy) { p.DNS.Servers = nil },
		"DNS missing search list":    func(p *Policy) { p.DNS.SearchDomains = nil },
		"DNS manual empty":           func(p *Policy) { p.DNS.Servers = []string{} },
		"DNS excessive":              func(p *Policy) { p.DNS.Servers = append(p.DNS.Servers, "203.0.113.53", "203.0.113.54") },
		"DNS duplicate":              func(p *Policy) { p.DNS.Servers = append(p.DNS.Servers, p.DNS.Servers[0]) },
		"DNS manual source":          func(p *Policy) { p.DNS.Source = "lan-1" },
		"DNS invalid mode":           func(p *Policy) { p.DNS.Mode = "system" },
		"DNS automatic static": func(p *Policy) {
			p.DNS = DNS{Mode: "automatic", Source: "lan-1", Servers: []string{}, SearchDomains: []string{}}
		},
		"DNS uppercase domain": func(p *Policy) { p.DNS.SearchDomains = []string{"Example.invalid"} },
		"DNS trailing dot":     func(p *Policy) { p.DNS.SearchDomains = []string{"test.invalid."} },
		"DNS duplicate search": func(p *Policy) { p.DNS.SearchDomains = append(p.DNS.SearchDomains, p.DNS.SearchDomains[0]) },
		"DNS excessive search": func(p *Policy) { p.DNS.SearchDomains = make([]string, MaxSearchDomains+1) },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			p := fixture()
			change(&p)
			if !errors.Is(p.Validate(), ErrInvalid) {
				t.Fatal("accepted unsafe policy")
			}
			data, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			got, err := Decode(bytes.NewReader(data))
			if !errors.Is(err, ErrInvalid) || !reflect.DeepEqual(got, Policy{}) {
				t.Fatal("decode did not fail closed")
			}
		})
	}
	for _, addr := range []string{"0.1.2.3/16", "127.0.0.1/8", "169.254.1.10/16", "224.0.0.1/24", "240.0.0.1/24", "192.0.0.0/16", "192.0.255.255/16", "192.0.2.10/0", "192.0.2.10/33", "192.000.2.10/24", " 192.0.2.10/24", "2001:db8::10/64"} {
		p := fixture()
		p.Interfaces[0].IPv4.Addresses = []string{addr}
		if p.Validate() == nil {
			t.Fatal("accepted invalid IPv4 prefix")
		}
	}
	for _, addr := range []string{"::/64", "::1/128", "::2/128", "fec0::10/64", "100::10/64", "fe80::10/64", "ff02::1/64", "::ffff:192.0.2.10/128", "2001:DB8::10/64", "2001:db8::10/0", "2001:db8::10%eth0/64"} {
		p := fixture()
		p.Interfaces[0].IPv6.Addresses = []string{addr}
		if p.Validate() == nil {
			t.Fatal("accepted invalid IPv6 prefix")
		}
	}
	for _, server := range []string{"localhost", "fe80::1", "fe80::1%lan-1", "::ffff:192.0.2.1", "224.0.0.1", "0.0.0.0", "192.0.2.1\n"} {
		p := fixture()
		p.DNS.Servers = []string{server}
		if p.Validate() == nil {
			t.Fatal("accepted unsafe DNS server")
		}
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("private upstream detail") }

func TestStrictDecodeAndRedaction(t *testing.T) {
	data, _ := json.Marshal(fixture())
	valid := string(data)
	inputs := []string{
		`null`, `{}`, valid + `{}`, valid + ` false`,
		strings.Replace(valid, `"revision":1`, `"revision":1,"revision":2`, 1),
		strings.Replace(valid, `"revision":1`, `"Revision":1`, 1),
		strings.Replace(valid, `"revision":1`, `"revision":-1`, 1),
		strings.Replace(valid, `"revision":1`, `"revision":1.0`, 1),
		strings.Replace(valid, `"revision":1`, `"revision":18446744073709551616`, 1),
		strings.Replace(valid, `"metric":100`, `"metric":65536`, 1),
		strings.Replace(valid, `"mode":"static"`, `"mode":"static","hostname":"private"`, 1),
		strings.Replace(valid, `"hostname":"nas-test"`, `"hostname":null`, 1),
		strings.Replace(valid, `"hostname":"nas-test"`, `"hostname":"\ud800"`, 1),
		strings.Replace(valid, `"hostname":"nas-test"`, "\"hostname\":\"\xff\"", 1),
		strings.Repeat(" ", MaxInputBytes) + valid,
		strings.Replace(valid, `"hostname":"nas-test"`, `"hostname":`+strings.Repeat("[", 10)+`"private"`+strings.Repeat("]", 10), 1),
	}
	for _, input := range inputs {
		got, err := Decode(strings.NewReader(input))
		if err != ErrInvalid || !reflect.DeepEqual(got, Policy{}) {
			t.Fatal("strict decoding leaked partial result")
		}
	}
	for _, r := range []io.Reader{nil, failingReader{}} {
		if _, err := Decode(r); err != ErrInvalid || strings.Contains(err.Error(), "private") {
			t.Fatal("error not redacted")
		}
	}
}

func TestBoundedMutationProperty(t *testing.T) {
	seed, _ := json.Marshal(fixture())
	rng := rand.New(rand.NewPCG(601, 20261003))
	for range 3000 {
		data := bytes.Clone(seed)
		for range 1 + rng.IntN(8) {
			data[rng.IntN(len(data))] = byte(rng.IntN(256))
		}
		p, err := Decode(bytes.NewReader(data))
		if err != nil {
			if err != ErrInvalid || !reflect.DeepEqual(p, Policy{}) {
				t.Fatal("failure contract")
			}
			continue
		}
		if p.Validate() != nil {
			t.Fatal("accepted policy fails validation")
		}
		encoded, e := json.Marshal(p)
		if e != nil {
			t.Fatal(e)
		}
		again, e := Decode(bytes.NewReader(encoded))
		if e != nil || !reflect.DeepEqual(p, again) {
			t.Fatal("round-trip contract")
		}
	}
}

func FuzzDecode(f *testing.F) {
	seed, _ := json.Marshal(fixture())
	f.Add(seed)
	f.Add([]byte(`{"format":"phantowd-network-policy","schema_version":1}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := Decode(bytes.NewReader(data))
		if err != nil {
			if err != ErrInvalid || !reflect.DeepEqual(p, Policy{}) {
				t.Fatal("failure contract")
			}
			return
		}
		if p.Validate() != nil {
			t.Fatal("accepted invalid policy")
		}
		encoded, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		again, err := Decode(bytes.NewReader(encoded))
		if err != nil || !reflect.DeepEqual(p, again) {
			t.Fatal("round-trip contract")
		}
	})
}
