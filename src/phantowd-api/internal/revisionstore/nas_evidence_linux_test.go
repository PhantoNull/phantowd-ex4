//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package revisionstore

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicyevidence"
)

const evidenceInstallation = "11111111111111111111111111111111"

func nasEvidenceFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	base, err := json.Marshal(nasKillPolicy(1))
	if err != nil {
		t.Fatal(err)
	}
	current, err := json.Marshal(nasKillPolicy(2))
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]any{"format": naspolicyevidence.IntentFormat, "schema_version": 1,
		"installation_id": evidenceInstallation, "operation_id": "22222222222222222222222222222222",
		"base_revision": 1, "next_revision": 2, "base_sha256": fmt.Sprintf("%x", sha256.Sum256(base)),
		"next_sha256": fmt.Sprintf("%x", sha256.Sum256(current))}
	intent, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	fields["format"], fields["phase"] = naspolicyevidence.ReceiptFormat, "local-confirmed"
	receipt, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"nas-evidence.json": []byte(`{"format":"phantowd-nas-evidence-container","schema_version":1,"installation_id":"` + evidenceInstallation + `"}`),
		"nas-services.json": current, ".nas-services.intent": intent,
		".nas-services.receipt": receipt, ".nas-services.base": base,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestNASEvidenceContainerRefusalsNeverBecomeCleanOrReleaseLock(t *testing.T) {
	for _, tc := range []struct {
		name, role, payload string
		want                naspolicyevidence.Kind
	}{
		{"missing-header", "nas-evidence.json", "", naspolicyevidence.Unavailable},
		{"missing-current", "nas-services.json", "", naspolicyevidence.Unavailable},
		{"foreign-header", "nas-evidence.json", `{"format":"phantowd-nas-evidence-container","schema_version":1,"installation_id":"22222222222222222222222222222222"}`, naspolicyevidence.Unavailable},
		{"unknown-role", "unknown", "evidence", naspolicyevidence.Unavailable},
		{"oversized-record", ".nas-services.intent", strings.Repeat(" ", naspolicyevidence.MaxRecordBytes+1), naspolicyevidence.Unavailable},
		{"pending", ".nas-services.pending", "never decoded", naspolicyevidence.Inconsistent},
		{"invalid-current", "nas-services.json", "{", naspolicyevidence.InvalidPolicy},
		{"base-disagrees", ".nas-services.base", "{}", naspolicyevidence.Inconsistent},
		{"invalid-intent", ".nas-services.intent", "{}", naspolicyevidence.Inconsistent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, ctx := nasEvidenceFixture(t), context.Background()
			path := filepath.Join(dir, tc.role)
			err := os.Remove(path)
			if tc.payload != "" {
				err = os.WriteFile(path, []byte(tc.payload), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			a, err := OpenNASEvidenceAuthority(ctx, dir, evidenceInstallation)
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			got, err := a.Observe(ctx)
			if tc.want == naspolicyevidence.Unavailable && (!errors.Is(err, ErrReview) || got != (NASEvidenceObservation{})) || tc.want != naspolicyevidence.Unavailable && (err != nil || got.Kind != tc.want) {
				t.Fatal("refusal was partial or clean", got, err)
			}
			if _, err := a.Observe(ctx); !errors.Is(err, ErrReview) {
				t.Fatal("review was not retained", err)
			}
			if other, err := OpenNASEvidenceAuthority(ctx, dir, evidenceInstallation); !errors.Is(err, ErrBusy) {
				if other != nil {
					other.Close()
				}
				t.Fatal("refusal released original lock", err)
			}
			if err := a.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := a.Observe(ctx); !errors.Is(err, ErrClosed) {
				t.Fatal("closed collector did not report closure", err)
			}
		})
	}
}

func TestNASEvidenceContainerRetainsOriginalReadOnlyNamespace(t *testing.T) {
	dir, ctx := nasEvidenceFixture(t), context.Background()
	a, err := OpenNASEvidenceAuthority(ctx, dir, evidenceInstallation)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	for range 2 {
		got, err := a.Observe(ctx)
		if err != nil || got.Kind != naspolicyevidence.MatchingLocalRecords || !got.BasePresent || got.Pending || got.Roles != 5 {
			t.Fatal("complete original evidence unavailable", got, err)
		}
		if other, err := OpenNASEvidenceAuthority(ctx, dir, evidenceInstallation); !errors.Is(err, ErrBusy) {
			if other != nil {
				other.Close()
			}
			t.Fatal("original container lock released", err)
		}
	}
	copy := *a
	if _, err := copy.Observe(ctx); !errors.Is(err, ErrInvalid) {
		t.Fatal("copied authority accepted", err)
	}
	if err := copy.Close(); !errors.Is(err, ErrInvalid) {
		t.Fatal("copy released original authority", err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := ObserveBootstrapWithCodec(ctx, dir, nasKillCodec())
	if err != nil || got.Kind != BootstrapUnrecognizedEntries {
		t.Fatal("legacy two-name census widened", got, err)
	}
}
