//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package revisionstore

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicyevidence"
	"golang.org/x/sys/unix"
)

func TestNASEvidenceCaptureCompleteOrEmptyWithoutChangingReader(t *testing.T) {
	for _, kind := range []string{"complete", "pending", "invalid-policy", "foreign", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			dir, ctx := nasEvidenceFixture(t), context.Background()
			if kind == "pending" || kind == "foreign" {
				role := ".nas-services.pending"
				if kind == "foreign" {
					role = "foreign"
				}
				if err := os.WriteFile(filepath.Join(dir, role), []byte{0xff, 0, 1}, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "invalid-policy" {
				if err := os.WriteFile(filepath.Join(dir, "nas-services.json"), []byte("{"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			a, err := OpenNASEvidenceAuthority(ctx, dir, evidenceInstallation)
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			if kind == "canceled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			set, err := collectNASEvidenceSet(ctx, a.root.root, a.root.initial, evidenceInstallation)
			if kind == "foreign" || kind == "canceled" {
				if err == nil || set.files != nil || set.observation != (NASEvidenceObservation{}) {
					t.Fatal("refusal exposed partial capture", err)
				}
				return
			}
			want, count := naspolicyevidence.MatchingLocalRecords, 5
			if kind == "pending" {
				want, count = naspolicyevidence.Inconsistent, 6
			}
			if kind == "invalid-policy" {
				want = naspolicyevidence.InvalidPolicy
			}
			if err != nil || len(set.files) != count || set.observation.Kind != want {
				t.Fatal("incomplete capture", err)
			}
			for name, file := range set.files {
				var st unix.Stat_t
				if unix.Fstatat(int(a.root.root.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW) != nil || policyStamp(st) != policyStamp(file.stat) {
					t.Fatal("captured metadata differs")
				}
				if name == ".nas-services.pending" {
					if file.data != nil {
						t.Fatal("pending body captured")
					}
					continue
				}
				got, err := os.ReadFile(filepath.Join(dir, name))
				if err != nil || !bytes.Equal(got, file.data) {
					t.Fatal("captured bytes differ", err)
				}
			}
			if got, err := a.Observe(ctx); err != nil || got != set.observation {
				t.Fatal("existing reader changed", got, err)
			}
		})
	}
}
