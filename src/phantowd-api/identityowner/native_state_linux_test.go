// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package identityowner

import (
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
)

func TestNativeIdentityDocumentRequiresTheSameGroupBeforeUser(t *testing.T) {
	first := serviceaccounts.Account{ID: "alpha", Name: "alpha", UID: 23700, GID: 23700, State: serviceaccounts.Disabled}
	other := serviceaccounts.Account{ID: "other", Name: "other", UID: 23701, GID: 23701, State: serviceaccounts.Disabled}
	empty := nativeIdentityDocument{Format: nativeIdentityFormat, Revision: 1, Records: []nativeIdentityRecord{}}
	group := nativeIdentityDocument{Format: nativeIdentityFormat, Revision: 2, Records: []nativeIdentityRecord{{first, nativeGroup}}}
	user := nativeIdentityDocument{Format: nativeIdentityFormat, Revision: 3, Records: []nativeIdentityRecord{{first, nativeUser}}}
	if validateNativeDocument(empty) != nil || validateNativeDocument(group) != nil || validateNativeDocument(user) != nil ||
		validateNativeTransition(empty, group) != nil || validateNativeTransition(group, user) != nil {
		t.Fatal("valid native identity creation sequence was refused")
	}
	replacement := nativeIdentityDocument{Format: nativeIdentityFormat, Revision: 3, Records: []nativeIdentityRecord{{other, nativeUser}}}
	if validateNativeTransition(empty, user) == nil || validateNativeTransition(group, replacement) == nil ||
		validateNativeTransition(user, group) == nil {
		t.Fatal("native state accepted a skipped, replaced, or regressed identity")
	}
	duplicate := nativeIdentityDocument{Format: nativeIdentityFormat, Revision: 4, Records: []nativeIdentityRecord{{first, nativeUser}, {first, nativeGroup}}}
	if validateNativeDocument(duplicate) == nil {
		t.Fatal("native state accepted a second reservation for the same identity")
	}
}
