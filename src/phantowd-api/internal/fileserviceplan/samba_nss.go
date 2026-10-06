// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package fileserviceplan

import (
	"fmt"
	"slices"
	"strings"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

// This is a combined NSS candidate limit, not the full protected configuration
// roster's budget. The later constructor must also bound its entire roster.
const MaxSambaNSSBytes = 32 << 10

const sambaFilesOnlyNSS = "passwd: files\ngroup: files\ninitgroups: files\nshadow: files\nhosts: files\nnetworks: files\nprotocols: files\nservices: files\n"

func renderSambaNSS(policy shareconfig.Config, registry serviceaccounts.Registry) (string, string, string, error) {
	bound, err := registry.BindShares(policy)
	if err != nil || len(bound.Accounts) > shareconfig.MaxUsers {
		return "", "", "", ErrNotReady
	}
	return renderNativeSambaNSS(bound.Accounts)
}

// Share grants and enrollment have separate admission/evidence contracts but
// the exact same locked private-identity document grammar. Clone before sorting
// so rendering never changes a caller's ledger or evidence order.
func renderNativeSambaNSS(accounts []serviceaccounts.Account) (string, string, string, error) {
	registry, err := serviceaccounts.New(1000, 60000)
	registry.Accounts = slices.Clone(accounts)
	if err != nil || registry.Validate() != nil || len(accounts) > serviceaccounts.MaxLive {
		return "", "", "", ErrNotReady
	}
	for _, account := range registry.Accounts {
		if account.State == serviceaccounts.Retired {
			return "", "", "", ErrNotReady
		}
	}
	slices.SortFunc(registry.Accounts, func(a, b serviceaccounts.Account) int { return strings.Compare(a.Name, b.Name) })
	var passwd, group strings.Builder
	// Fixed lookup identities required by a standalone Samba root; these do not
	// grant SMB login. Both names are reserved by the native registry. In
	// particular, do not invent a nogroup entry that collides with valid names.
	passwd.WriteString("root:!:0:0:root:/:/sbin/nologin\nnobody:!:65534:65534:nobody:/:/sbin/nologin\n")
	group.WriteString("root:!:0:\nnobody:!:65534:\n")
	for _, account := range registry.Accounts {
		// Native accounts already require same-number private primary groups.
		// No supplementary groups, shadow/credentials, homes or imported IDs.
		fmt.Fprintf(&passwd, "%s:!:%d:%d::/:/sbin/nologin\n", account.Name, account.UID, account.GID)
		fmt.Fprintf(&group, "%s:!:%d:\n", account.Name, account.GID)
	}
	if passwd.Len()+group.Len()+len(sambaFilesOnlyNSS) > MaxSambaNSSBytes {
		return "", "", "", ErrNotReady
	}
	return passwd.String(), group.String(), sambaFilesOnlyNSS, nil
}

// SambaNSSCandidates returns immutable candidate documents from this exact
// plan, sharing its freshness tuple. BuildFromOwners derives them under the
// existing Owner locks; Build's supplied snapshots remain caller evidence.
// These strings neither install NSS nor retain identity/passdb authority.
func (p Plan) SambaNSSCandidates() (passwd, group, nss string, err error) {
	if p.scope != "candidate-only" || p.sambaPasswd == "" || p.sambaGroup == "" || p.sambaNSS == "" {
		return "", "", "", ErrNotReady
	}
	return p.sambaPasswd, p.sambaGroup, p.sambaNSS, nil
}
