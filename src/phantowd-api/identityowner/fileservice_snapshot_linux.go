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
)

const fileServiceSnapshotFormat = "phantowd-file-service-identity-evidence-v1"

// FileServiceSamba binds a durable Owner-managed journal to its latest
// validated, redacted passdb observation.
type FileServiceSamba struct {
	Journal     smbprovision.Journal
	Observation smbprovision.Observation
}

// FileServicePassdb is aligned by AccountID with one Owner registry entry. It
// includes accounts with no Samba journal so unexpected pre-existing passdb
// records cannot silently be treated as absent.
type FileServicePassdb struct {
	AccountID   string
	Observation smbprovision.Observation
}

// FileServiceSnapshot is an internal, all-or-error evidence bundle. UID, GID,
// and name reservations are private host identity census data; callers must
// not expose or persist this value. Fingerprint covers the exact registry,
// journals, Unix reservations, and redacted passdb observations collected.
type FileServiceSnapshot struct {
	Registry    serviceaccounts.Registry
	Native      []identityprovision.Journal
	UIDs        []uint32
	GIDs        []uint32
	Names       []string
	Samba       []FileServiceSamba
	Passdb      []FileServicePassdb
	Fingerprint [32]byte
}

// FileServiceSnapshot obtains complete Owner-managed identity evidence under
// the same lock used by Unix and Samba mutations. It deliberately avoids the
// ordinary snapshot/recovery path: interrupted SMB intents and existing
// review-required states fail closed without being rewritten or retried. The
// one-pass backend must return only requested redacted rows and fail atomically.
func (o *Owner) FileServiceSnapshot(ctx context.Context) (FileServiceSnapshot, error) {
	var evidence FileServiceSnapshot
	err := o.WithFileServiceSnapshot(ctx, func(snapshot FileServiceSnapshot) error {
		evidence = snapshot
		return nil
	})
	if err != nil {
		return FileServiceSnapshot{}, err
	}
	return evidence, nil
}

// WithFileServiceSnapshot invokes inspect while the identity Owner lock remains
// held. Callers may use it only for bounded trusted in-process derivation such
// as composing a candidate; inspect must not re-enter this Owner or perform
// process, filesystem, network, or service-activation I/O.
func (o *Owner) WithFileServiceSnapshot(ctx context.Context, inspect func(FileServiceSnapshot) error) error {
	if inspect == nil {
		return ErrUnavailable
	}
	if err := o.enter(ctx); err != nil {
		return err
	}
	defer o.mu.Unlock()
	evidence, err := o.fileServiceSnapshotLocked(ctx)
	if err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ErrUnavailable
	}
	if err := inspect(evidence); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ErrUnavailable
	}
	return nil
}

func (o *Owner) fileServiceSnapshotLocked(ctx context.Context) (FileServiceSnapshot, error) {
	registry, native, sambaJournals, reservations, err := o.nativeEvidenceLocked(ctx)
	if err != nil {
		return FileServiceSnapshot{}, err
	}
	sambaByID := make(map[string]smbprovision.Journal, len(sambaJournals))
	for _, journal := range sambaJournals {
		sambaByID[journal.Account.ID] = journal
	}

	passdb := make([]FileServicePassdb, len(registry.Accounts))
	observations := make([]smbprovision.Observation, len(registry.Accounts))
	if len(registry.Accounts) > 0 {
		observer, ok := o.smbBackend.(smbprovision.BatchObserver)
		if !ok || observer == nil {
			return FileServiceSnapshot{}, ErrUnavailable
		}
		observations, err = observer.ObserveAccounts(ctx, registry.Accounts)
		if err != nil || ctx.Err() != nil || len(observations) != len(registry.Accounts) {
			return FileServiceSnapshot{}, ErrUnavailable
		}
	}

	samba := make([]FileServiceSamba, 0, len(sambaJournals))
	for i, account := range registry.Accounts {
		if err := ctx.Err(); err != nil {
			return FileServiceSnapshot{}, ErrUnavailable
		}
		observed := observations[i]
		passdb[i] = FileServicePassdb{AccountID: account.ID, Observation: observed}
		journal, exists := sambaByID[account.ID]
		if !exists {
			if observed.Present || observed.Name != "" || observed.UID != 0 || observed.GID != 0 || observed.SID != "" || observed.Disabled {
				return FileServiceSnapshot{}, errors.Join(ErrReview, smbprovision.ErrObservation)
			}
			continue
		}
		if err := journal.ValidateObservation(observed); err != nil {
			if errors.Is(err, smbprovision.ErrReview) || errors.Is(err, smbprovision.ErrObservation) {
				return FileServiceSnapshot{}, errors.Join(ErrReview, err)
			}
			return FileServiceSnapshot{}, ErrUnavailable
		}
		samba = append(samba, FileServiceSamba{Journal: journal, Observation: observed})
	}

	if err := ctx.Err(); err != nil {
		return FileServiceSnapshot{}, ErrUnavailable
	}
	snapshot := FileServiceSnapshot{
		Registry: registry, Native: native,
		UIDs: reservations.UIDs, GIDs: reservations.GIDs, Names: reservations.Names,
		Samba: samba, Passdb: passdb,
	}
	encoded, err := json.Marshal(struct {
		Format   string
		Registry serviceaccounts.Registry
		Native   []identityprovision.Journal
		UIDs     []uint32
		GIDs     []uint32
		Names    []string
		Samba    []FileServiceSamba
		Passdb   []FileServicePassdb
	}{fileServiceSnapshotFormat, snapshot.Registry, snapshot.Native, snapshot.UIDs, snapshot.GIDs, snapshot.Names, snapshot.Samba, snapshot.Passdb})
	if err != nil {
		return FileServiceSnapshot{}, ErrUnavailable
	}
	snapshot.Fingerprint = sha256.Sum256(encoded)
	clear(encoded)
	return snapshot, nil
}

// File-service evidence is process-local and includes host identity census
// material; it must not accidentally cross an HTTP, log, or persistence seam.
func (FileServiceSnapshot) MarshalJSON() ([]byte, error) {
	return nil, errors.New("internal file-service identity evidence is not serializable")
}

func (*FileServiceSnapshot) UnmarshalJSON([]byte) error {
	return errors.New("internal file-service identity evidence cannot be deserialized")
}
