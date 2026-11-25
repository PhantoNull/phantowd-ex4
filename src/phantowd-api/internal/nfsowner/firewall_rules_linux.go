// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package nfsowner

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"
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

type nftObject = map[string]any

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

func nfsPortExpression(protocol string) nftObject {
	ports := make([]any, len(nfsPorts))
	for i, port := range nfsPorts {
		ports[i] = json.Number(strconv.Itoa(port))
	}
	return nftMatch(nftPayload(protocol, "dport"), nftObject{"set": ports})
}

func nftMatch(left, right any) nftObject {
	return nftObject{"match": nftObject{"op": "==", "left": left, "right": right}}
}

func nftPayload(protocol, field string) nftObject {
	return nftObject{"payload": nftObject{"protocol": protocol, "field": field}}
}

func (r nfsFirewallRules) ingress(key, value string, source any) []any {
	return []any{
		nftMatch(nftObject{"meta": nftObject{"key": key}}, value),
		nftMatch(nftPayload("ip", "saddr"), source),
		nftMatch(nftPayload("ip", "daddr"), r.address.String()),
		nfsPortExpression("tcp"),
		nftObject{"accept": nil},
	}
}

func (r nfsFirewallRules) snapshot(objects []nftObject) (uint64, error) {
	if len(objects) != 5+len(r.sources) {
		return 0, ErrState
	}
	handle, err := matchNFTObject(objects[0], "table", nftObject{
		"family": "inet", "name": nfsTable, "comment": r.token,
	})
	if err != nil {
		return 0, err
	}
	if _, err := matchNFTObject(objects[1], "chain", nftObject{
		"family": "inet", "table": nfsTable, "name": nfsInput,
		"type": "filter", "hook": "input", "prio": json.Number(strconv.Itoa(nfsPriority)), "policy": "accept",
	}); err != nil {
		return 0, err
	}
	rules := [][]any{r.ingress("iifname", "lo", r.address.String())}
	for _, prefix := range r.sources {
		var source any = prefix.Addr().String()
		if prefix.Bits() != 32 {
			source = nftObject{"prefix": nftObject{"addr": source, "len": json.Number(strconv.Itoa(prefix.Bits()))}}
		}
		rules = append(rules, r.ingress("iif", r.name, source))
	}
	for _, protocol := range []string{"tcp", "udp"} {
		rules = append(rules, []any{nfsPortExpression(protocol), nftObject{"drop": nil}})
	}
	for i, expr := range rules {
		if _, err := matchNFTObject(objects[i+2], "rule", nftObject{
			"family": "inet", "table": nfsTable, "chain": nfsInput, "expr": expr,
		}); err != nil {
			return 0, err
		}
	}
	return handle, nil
}

func matchNFTObject(wrapper nftObject, kind string, want nftObject) (uint64, error) {
	object, ok := wrapper[kind].(map[string]any)
	if !ok || len(wrapper) != 1 {
		return 0, ErrState
	}
	number, ok := object["handle"].(json.Number)
	handle, err := strconv.ParseUint(string(number), 10, 64)
	if !ok || err != nil || handle == 0 {
		return 0, ErrState
	}
	delete(object, "handle")
	if !reflect.DeepEqual(object, want) {
		return 0, ErrState
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
