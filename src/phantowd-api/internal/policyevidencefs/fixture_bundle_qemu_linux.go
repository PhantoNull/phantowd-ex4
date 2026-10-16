//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policyevidencefs

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/policyevidence"
)

// Synthetic data only, under the fresh verified tmpfs fixture root. This wire
// is intentionally constructed independently of the transaction codec; it is
// not a writer result or a claim about earlier synchronization.
func exerciseBundleObservationQEMU(ctx context.Context, root string, base, current, intent, receipt []byte) error {
	const installation = "11111111222233334444555555555555"
	makeLayout := func(name string, cur []byte, confirmed, absent bool) (string, error) {
		dir := filepath.Join(root, "bundle-"+name)
		if os.Mkdir(dir, 0700) != nil {
			return "", ErrIO
		}
		for _, child := range []string{"policy", "operations"} {
			if os.Mkdir(filepath.Join(dir, child), 0700) != nil {
				return "", ErrIO
			}
		}
		if cur != nil && os.WriteFile(filepath.Join(dir, "policy/nas-services.json"), cur, 0600) != nil {
			return "", ErrIO
		}
		if !absent {
			phase, revision, rc := "intent", 1, []byte(nil)
			if confirmed {
				phase, revision, rc = "local-confirmed", 2, receipt
			}
			wire, err := json.Marshal(map[string]any{"format": "phantowd-policy-operation-bundle-experimental", "schema_version": 1,
				"revision": revision, "phase": phase, "installation_id": installation, "base": base64.StdEncoding.EncodeToString(base),
				"intent": base64.StdEncoding.EncodeToString(intent), "receipt": base64.StdEncoding.EncodeToString(rc)})
			if err != nil || os.WriteFile(filepath.Join(dir, "operations/operation.json"), wire, 0600) != nil {
				return "", ErrIO
			}
		}
		return dir, nil
	}
	for _, tc := range []struct {
		name              string
		current           []byte
		confirmed, absent bool
		want              policyevidence.Kind
	}{
		{"empty-operation", current, false, true, policyevidence.NoRecordedOperation},
		{"base", base, false, false, policyevidence.IntentBaseObserved},
		{"published", current, false, false, policyevidence.PublicationUnconfirmed},
		{"confirmed", current, true, false, policyevidence.LocalConfirmationObserved},
		{"inconsistent", base, true, false, policyevidence.InconsistentEvidence},
		{"missing-current", nil, true, false, policyevidence.IncompleteEvidence},
	} {
		dir, err := makeLayout(tc.name, tc.current, tc.confirmed, tc.absent)
		if err != nil {
			return err
		}
		a, err := OpenBundle(ctx, dir, installation)
		if err != nil {
			return err
		}
		for range 2 {
			d, err := a.Observe(ctx)
			if err != nil || d.Kind() != tc.want {
				_ = a.Close()
				return ErrReview
			}
		}
		if a.Close() != nil {
			return ErrReview
		}
	}
	for _, scenario := range []string{"policy-pending", "operation-pending", "read-failure", "cancel", "restoration", "mixed-profile", "legacy-opener"} {
		dir, err := makeLayout(scenario, current, true, false)
		if err != nil {
			return err
		}
		if scenario == "mixed-profile" && os.WriteFile(filepath.Join(dir, "operations/intent.json"), intent, 0600) != nil {
			return ErrIO
		}
		pending := ""
		if scenario == "policy-pending" {
			pending = "policy/.nas-services.pending"
		}
		if scenario == "operation-pending" {
			pending = "operations/.operation.pending"
		}
		if pending != "" && os.WriteFile(filepath.Join(dir, pending), []byte("malformed staged bytes never parsed"), 0600) != nil {
			return ErrIO
		}
		opener := OpenBundle
		if scenario == "legacy-opener" {
			opener = Open
		}
		a, err := opener(ctx, dir, installation)
		if scenario == "mixed-profile" || scenario == "legacy-opener" {
			if a != nil {
				_ = a.Close()
				return ErrReview
			}
			if !errors.Is(err, ErrUnsafe) {
				return ErrReview
			}
			continue
		}
		if err != nil {
			return err
		}
		local, cancel := context.WithCancelCause(ctx)
		reads := 0
		if pending != "" || scenario == "read-failure" {
			a.state.readAt = func(*os.File, []byte, int64) (int, error) {
				reads++
				return 0, errors.New("private injected read error")
			}
		}
		if scenario == "cancel" {
			a.state.beforeMatch = func() { cancel(errors.New("private injected cancellation")) }
		}
		if scenario == "restoration" {
			path := filepath.Join(dir, "operations/operation.json")
			if os.Chmod(path, 0400) != nil || os.Chmod(path, 0600) != nil {
				cancel(nil)
				_ = a.Close()
				return ErrIO
			}
		}
		d, observeErr := a.Observe(local)
		cancel(nil)
		if d.Kind() != "" || !errors.Is(observeErr, ErrReview) || strings.Contains(observeErr.Error(), "private injected") ||
			pending != "" && reads != 0 || scenario == "read-failure" && reads != 1 || scenario == "cancel" && !errors.Is(observeErr, context.Canceled) {
			_ = a.Close()
			return ErrReview
		}
		a.state.beforeMatch = nil
		for range 2 {
			if d, err := a.Observe(ctx); d.Kind() != "" || !errors.Is(err, ErrReview) {
				_ = a.Close()
				return ErrReview
			}
		}
		if a.Close() != nil {
			return ErrReview
		}
	}
	return nil
}
