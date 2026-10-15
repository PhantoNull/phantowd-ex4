//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package fileserviceplan

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
)

func TestLockedOwnerPlanningPreservesCanceledAdmissionWithoutObservations(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		for _, expiry := range []bool{false, true} {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			want := context.Canceled
			if expiry {
				time.Sleep(2 * time.Second)
				synctest.Wait()
				want = context.DeadlineExceeded
			} else {
				cancel()
			}
			// Deliberately ineligible set: the real admission guard must refuse
			// before any storage/identity observation, not fabricate healthy owners.
			identityCalls := 0
			plan, err := buildFromLockedOwners(ctx, fileservice.Config{}, 0, &mountowner.MountedVolumeSet{}, func(context.Context, func(identityowner.FileServiceSnapshot) error) error {
				identityCalls++
				return nil
			})
			cancel()
			if !errors.Is(err, ErrNotReady) || !errors.Is(err, want) || identityCalls != 0 || plan.FreshAgainst(plan.Freshness()) {
				t.Fatalf("canceled planning lost cause or observed/authorized inputs: err=%v observations=%d", err, identityCalls)
			}
		}
	})
}

func TestBuildFromOwnersRefusesMissingTrustedOwners(t *testing.T) {
	if _, err := BuildFromOwners(context.Background(), fileservice.Config{}, 0, nil, nil); !errors.Is(err, ErrNotReady) {
		t.Fatalf("missing identity and storage Owners must fail closed: %v", err)
	}
}

func TestBuildFromRetainedOwnersRefusesMissingAuthority(t *testing.T) {
	for _, ctx := range []context.Context{nil, context.Background()} {
		if _, err := BuildFromRetainedOwners(ctx, fileservice.Config{}, 0, nil, nil); !errors.Is(err, ErrNotReady) {
			t.Fatal("missing retained identity/storage authority supplied a plan:", err)
		}
	}
}
