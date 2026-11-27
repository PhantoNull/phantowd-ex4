// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package nfsowner

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/nftguard"
)

const (
	nfsTable    = "phantowd_nfs"
	nfsInput    = "input"
	nfsPriority = -10
)

type nfsFirewallRules struct {
	index   int
	name    string
	address netip.Addr
	sources []netip.Prefix
	token   string
}

func (r nfsFirewallRules) install() string {
	var b strings.Builder
	fmt.Fprintf(&b, "create table inet %s { comment %q; }\n", nfsTable, r.token)
	fmt.Fprintf(&b, "add chain inet %s %s { type filter hook input priority %d; policy accept; }\n", nfsTable, nfsInput, nfsPriority)
	fmt.Fprintf(&b, "add rule inet %s %s meta iifname \"lo\" ip saddr %s ip daddr %s tcp dport %s accept\n",
		nfsTable, nfsInput, r.address, r.address, nfsPortSet())
	for _, source := range r.sources {
		fmt.Fprintf(&b, "add rule inet %s %s meta iif %d ip saddr %s ip daddr %s tcp dport %s accept\n",
			nfsTable, nfsInput, r.index, source, r.address, nfsPortSet())
	}
	for _, protocol := range []string{"tcp", "udp"} {
		fmt.Fprintf(&b, "add rule inet %s %s %s dport %s drop\n", nfsTable, nfsInput, protocol, nfsPortSet())
	}
	return b.String()
}

var nfsPorts = [...]int{111, 2049, mountdPort}

func nfsPortSet() string {
	return fmt.Sprintf("{%d, %d, %d}", nfsPorts[0], nfsPorts[1], nfsPorts[2])
}

func nfsPortExpression(protocol string) nftguard.Object {
	ports := make([]any, len(nfsPorts))
	for i, port := range nfsPorts {
		ports[i] = json.Number(strconv.Itoa(port))
	}
	return nftguard.Match(nftguard.Payload(protocol, "dport"), nftguard.Object{"set": ports})
}

func (r nfsFirewallRules) ingress(key, value string, source any) []any {
	return []any{
		nftguard.Match(nftguard.Object{"meta": nftguard.Object{"key": key}}, value),
		nftguard.Match(nftguard.Payload("ip", "saddr"), source),
		nftguard.Match(nftguard.Payload("ip", "daddr"), r.address.String()),
		nfsPortExpression("tcp"),
		nftguard.Object{"accept": nil},
	}
}

func (r nfsFirewallRules) snapshot(objects []nftguard.Object) (uint64, error) {
	if len(objects) != 5+len(r.sources) {
		return 0, ErrState
	}
	handle, err := nftguard.MatchObject(objects[0], "table", nftguard.Object{
		"family": "inet", "name": nfsTable, "comment": r.token,
	})
	if err != nil {
		return 0, ErrState
	}
	if _, err := nftguard.MatchObject(objects[1], "chain", nftguard.Object{
		"family": "inet", "table": nfsTable, "name": nfsInput,
		"type": "filter", "hook": "input", "prio": json.Number(strconv.Itoa(nfsPriority)), "policy": "accept",
	}); err != nil {
		return 0, ErrState
	}
	rules := [][]any{r.ingress("iifname", "lo", r.address.String())}
	for _, prefix := range r.sources {
		var source any = prefix.Addr().String()
		if prefix.Bits() != 32 {
			source = nftguard.Object{"prefix": nftguard.Object{"addr": source, "len": json.Number(strconv.Itoa(prefix.Bits()))}}
		}
		rules = append(rules, r.ingress("iif", r.name, source))
	}
	for _, protocol := range []string{"tcp", "udp"} {
		rules = append(rules, []any{nfsPortExpression(protocol), nftguard.Object{"drop": nil}})
	}
	for i, expr := range rules {
		if _, err := nftguard.MatchObject(objects[i+2], "rule", nftguard.Object{
			"family": "inet", "table": nfsTable, "chain": nfsInput, "expr": expr,
		}); err != nil {
			return 0, ErrState
		}
	}
	return handle, nil
}

func normalizeNFSSources(sources []netip.Prefix) ([]netip.Prefix, error) {
	if len(sources) == 0 {
		return nil, ErrInvalid
	}
	out := slices.Clone(sources)
	for _, p := range out {
		if !p.Addr().Is4() || p.Bits() <= 0 || p != p.Masked() {
			return nil, ErrInvalid
		}
	}
	slices.SortFunc(out, func(a, b netip.Prefix) int {
		if order := a.Addr().Compare(b.Addr()); order != 0 {
			return order
		}
		return a.Bits() - b.Bits()
	})
	return slices.Compact(out), nil
}
