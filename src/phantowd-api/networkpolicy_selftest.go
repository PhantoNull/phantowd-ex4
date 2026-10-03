//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"errors"
	"strings"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/networkpolicy"
)

func exerciseQEMUNetworkPolicy() error {
	const fixture = `{"format":"phantowd-network-policy","schema_version":1,"revision":1,"hostname":"nas-test",
"interfaces":[{"slot":"lan-1","ipv4":{"mode":"static","addresses":["192.0.2.10/16","192.0.2.11/16"],"default_route":true,"gateway":"192.0.2.1","metric":100},
"ipv6":{"mode":"static","addresses":["2001:db8:1::10/64"],"default_route":true,"gateway":"fe80::1","metric":100}},
{"slot":"lan-2","ipv4":{"mode":"dhcp","addresses":[],"default_route":true,"metric":200},
"ipv6":{"mode":"auto","addresses":[],"default_route":true,"metric":200}}],
"routes":[{"slot":"lan-1","destination":"198.51.100.0/24","gateway":"192.0.2.2","metric":300}],
"dns":{"mode":"automatic","source":"lan-2","servers":[],"search_domains":["test.invalid"]}}`
	p, err := networkpolicy.Decode(strings.NewReader(fixture))
	if err != nil || p.Validate() != nil || p.Interfaces[0].IPv4.Addresses[0] != "192.0.2.10/16" ||
		p.Interfaces[0].IPv6.Gateway != "fe80::1" || len(p.Routes) != 1 || p.DNS.Source != "lan-2" {
		return errors.New("desired network policy lost dual-stack constraints")
	}
	for _, input := range []string{
		strings.Replace(fixture, `"addresses":["192.0.2.10/16","192.0.2.11/16"]`, `"addresses":["192.0.2.10/16","192.0.2.10/24"]`, 1),
		strings.Replace(fixture, `"mode":"dhcp","addresses":[]`, `"mode":"static","addresses":["192.0.3.10/24"],"gateway":"192.0.3.1"`, 1),
		strings.Replace(fixture, `"metric":200`, `"metric":100`, 1),
		strings.Replace(fixture, `"gateway":"fe80::1"`, `"gateway":"fe80::1%eth0"`, 1),
		strings.Replace(fixture, `"revision":1`, `"revision":1,"revision":2`, 1),
		strings.Replace(fixture, `"source":"lan-2"`, `"source":"lan-1"`, 1),
		strings.Replace(fixture, `"slot":"lan-2"`, `"slot":"eth0"`, 1),
	} {
		if _, err := networkpolicy.Decode(strings.NewReader(input)); err != networkpolicy.ErrInvalid {
			return errors.New("desired network policy accepted an unsafe fixture")
		}
	}
	return nil
}
