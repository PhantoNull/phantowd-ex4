//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package identityowner

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityprovision"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smbprovision"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/unixidentity"
)

const nativeLookupFormat = "phantowd-native-lookup-evidence-v1"

// NativeLookupSnapshot is private process-local lookup evidence, including
// confirmed disabled identities before Samba enrollment. It asserts neither
// passdb absence nor credential readiness, grants, storage or service authority.
// Samba contains only existing stable journals, never a live passdb observation.
// Fingerprint is a point-in-time change detector, not a retained identity lease.
type NativeLookupSnapshot struct {
	Registry    serviceaccounts.Registry
	Native      []identityprovision.Journal
	Samba       []smbprovision.Journal
	UIDs        []uint32
	GIDs        []uint32
	Names       []string
	Fingerprint [32]byte
}

// NativeLookupSnapshot reads known journals without recovery and freshly checks
// all native identities under the Owner mutation lock. It requires no Samba
// backend and performs no credential observation or mutation. It is not exposed
// over the Owner socket, HTTP or product startup.
func (o *Owner) NativeLookupSnapshot(ctx context.Context) (NativeLookupSnapshot, error) {
	var result NativeLookupSnapshot
	err := o.WithNativeLookupSnapshot(ctx, func(snapshot NativeLookupSnapshot) error {
		result = snapshot
		return nil
	})
	if err != nil {
		return NativeLookupSnapshot{}, err
	}
	return result, nil
}

// WithNativeLookupSnapshot keeps the Owner lock through bounded in-process
// derivation only. inspect must not re-enter the Owner, perform I/O, wait for
// processes or activate services. Staging/retention needs a separate constructor.
func (o *Owner) WithNativeLookupSnapshot(ctx context.Context, inspect func(NativeLookupSnapshot) error) error {
	if inspect == nil {
		return ErrUnavailable
	}
	if err := o.enter(ctx); err != nil {
		return err
	}
	defer o.mu.Unlock()
	registry, native, samba, reserved, err := o.nativeEvidenceLocked(ctx)
	if err != nil {
		return err
	}
	snapshot := NativeLookupSnapshot{Registry: registry, Native: native, Samba: samba,
		UIDs: reserved.UIDs, GIDs: reserved.GIDs, Names: reserved.Names}
	encoded, err := json.Marshal(struct {
		Format   string
		Registry serviceaccounts.Registry
		Native   []identityprovision.Journal
		Samba    []smbprovision.Journal
		UIDs     []uint32
		GIDs     []uint32
		Names    []string
	}{nativeLookupFormat, registry, native, samba, reserved.UIDs, reserved.GIDs, reserved.Names})
	if err != nil {
		return ErrUnavailable
	}
	snapshot.Fingerprint = sha256.Sum256(encoded)
	clear(encoded)
	if ctx.Err() != nil {
		return ErrUnavailable
	}
	if err := inspect(snapshot); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ErrUnavailable
	}
	return nil
}

// nativeEvidenceLocked is shared with the stronger file-service observation.
// Keep the complete known-journal and current Unix checks identical; the native
// lookup must not use ordinary snapshot's SMB recovery path as a shortcut.
func (o *Owner) nativeEvidenceLocked(ctx context.Context) (serviceaccounts.Registry, []identityprovision.Journal, []smbprovision.Journal, serviceaccounts.Reservations, error) {
	registry, native, samba, err := o.scanSnapshot(false)
	if err == nil {
		seen := make(map[string]bool, len(samba))
		for _, journal := range samba {
			if journal.Validate() != nil || seen[journal.Account.ID] {
				err = ErrUnavailable
				break
			}
			seen[journal.Account.ID] = true
			switch journal.Phase {
			case smbprovision.CreateIntent, smbprovision.PasswordIntent,
				smbprovision.EnableIntent, smbprovision.DisableIntent, smbprovision.ReviewRequired:
				err = ErrReview
			}
			if err != nil {
				break
			}
		}
	}
	var reserved serviceaccounts.Reservations
	if err == nil {
		reserved, err = o.observeConfirmedNativeLocked(ctx, registry, native)
	}
	if err != nil {
		return serviceaccounts.Registry{}, nil, nil, serviceaccounts.Reservations{}, err
	}
	return registry, native, samba, reserved, nil
}

func (o *Owner) observeConfirmedNativeLocked(ctx context.Context, registry serviceaccounts.Registry, native []identityprovision.Journal) (serviceaccounts.Reservations, error) {
	if ctx.Err() != nil {
		return serviceaccounts.Reservations{}, ErrUnavailable
	}
	local, err := o.deps.observe(ctx)
	if err != nil {
		return serviceaccounts.Reservations{}, ErrUnavailable
	}
	reserved, err := local.Reservations()
	if err != nil || reserved.UIDs == nil || reserved.GIDs == nil || reserved.Names == nil ||
		len(reserved.UIDs) > 65536 || len(reserved.GIDs) > 65536 || len(reserved.Names) > 65536 ||
		len(native) != len(registry.Accounts) {
		return serviceaccounts.Reservations{}, ErrUnavailable
	}
	for i, account := range registry.Accounts {
		journal := native[i]
		if ctx.Err() != nil {
			return serviceaccounts.Reservations{}, ErrUnavailable
		}
		if journal.Validate() != nil || journal.Phase != identityprovision.UnixConfirmed || !sameAccountIdentity(journal.Account, account) {
			if journal.Phase == identityprovision.ReviewRequired {
				return serviceaccounts.Reservations{}, ErrReview
			}
			return serviceaccounts.Reservations{}, ErrPending
		}
		status, err := local.Assess(account)
		if err != nil {
			return serviceaccounts.Reservations{}, ErrUnavailable
		}
		if status != unixidentity.Observed {
			return serviceaccounts.Reservations{}, ErrReview
		}
	}
	if ctx.Err() != nil {
		return serviceaccounts.Reservations{}, ErrUnavailable
	}
	return reserved, nil
}

func (NativeLookupSnapshot) MarshalJSON() ([]byte, error) {
	return nil, errors.New("internal native lookup evidence is not serializable")
}

func (*NativeLookupSnapshot) UnmarshalJSON([]byte) error {
	return errors.New("internal native lookup evidence cannot be deserialized")
}
