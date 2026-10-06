//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityprovision"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/unixidentity"
)

// This runs inside the existing diskless/disposable QEMU account fixture,
// after actual typed Unix creation but BEFORE its first Samba enrollment.
// Nothing is installed into the daemon root or passed to a credential backend.
func exerciseQEMUNativeEnrollmentLookup(owner *identityowner.Owner) error {
	if err := guardQEMUDataVolume(); err != nil {
		return err
	}
	ctx := context.Background()
	before, err := owner.NativeLookupSnapshot(ctx)
	if err != nil || len(before.Registry.Accounts) != 2 || len(before.Native) != 2 || len(before.Samba) != 0 {
		return errors.New("native enrollment lookup fixture not pre-enrollment")
	}
	lookup, err := fileserviceplan.SambaEnrollmentLookupFromOwner(ctx, owner)
	if err != nil || lookup.Fingerprint() != before.Fingerprint {
		return errors.New("native enrollment lookup not bound to confirmed Owner evidence")
	}
	passwd, group, nss, err := lookup.LookupDocuments()
	if err != nil || !unixidentity.FilesOnlyNSS([]byte(nss)) ||
		len(passwd)+len(group)+len(nss) > fileserviceplan.MaxSambaNSSBytes {
		return errors.New("native enrollment lookup document contract refused")
	}
	parsed, err := unixidentity.Parse(strings.NewReader(passwd), strings.NewReader(group))
	if err != nil {
		return errors.New("native enrollment lookup independent parse failed")
	}
	for i, account := range before.Registry.Accounts {
		if account.State != serviceaccounts.Disabled || account.UID != account.GID ||
			before.Native[i].Phase != identityprovision.UnixConfirmed {
			return errors.New("native enrollment lookup did not use disabled confirmed private identities")
		}
		if status, err := parsed.Assess(account); err != nil || status != unixidentity.Observed {
			return errors.New("native enrollment lookup does not resolve real generated account")
		}
		if !strings.Contains(passwd, fmt.Sprintf("%s:!:%d:%d::/:/sbin/nologin\n", account.Name, account.UID, account.GID)) {
			return errors.New("native enrollment lookup lost locked no-login identity")
		}
	}
	for _, name := range []string{"qpwriter", "qpreader", "qpoutsider", "qpgroup"} {
		if strings.Contains(passwd, name+":") || strings.Contains(group, name+":") {
			return errors.New("native enrollment lookup adopted unrelated fixture identity")
		}
	}
	if _, err := json.Marshal(before); err == nil {
		return errors.New("native enrollment evidence unexpectedly serializable")
	}
	if _, err := json.Marshal(lookup); err == nil {
		return errors.New("native enrollment documents unexpectedly serializable")
	}
	after, err := owner.NativeLookupSnapshot(ctx)
	if err != nil || !reflect.DeepEqual(before, after) {
		return errors.New("native enrollment lookup changed actual Owner state")
	}
	fmt.Println("PHANTOWD_M24_NATIVE_ENROLLMENT_LOOKUP_READY accounts=2 before_enrollment=true private_groups=true files_only=true foreign_omitted=true journals_unchanged=true json_refused=true installed=false activation=false scope=disposable-qemu-only")
	return nil
}
