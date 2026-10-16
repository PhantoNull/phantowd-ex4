//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policytransaction_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicystore"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/policyevidence"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/policyevidencefs"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/policytransaction"
)

func TestRuntimeBundleObserverAfterProcessLoss(t *testing.T) {
	for _, stage := range policytransaction.RuntimeBundleLossStages() {
		t.Run(stage, func(t *testing.T) {
			policytransaction.RunRuntimeBundleLossFixture(t, stage, func(ctx context.Context, root string, pending bool, want policyevidence.Kind) (result error) {
				a, err := policyevidencefs.OpenBundle(ctx, root, "11111111222233334444555555555555")
				if err != nil {
					return errors.New("runtime bundle open refused")
				}
				defer func() {
					if a.Close() != nil {
						result = errors.New("runtime bundle close uncertain")
					}
				}()
				for range 2 {
					d, err := a.Observe(ctx)
					if pending {
						if !errors.Is(err, policyevidencefs.ErrReview) || d.Kind() != "" {
							return errors.New("pending data became diagnosis")
						}
					} else if err != nil || d.Kind() != want {
						return errors.New("incorrect runtime diagnosis")
					}
				}
				// These are exclusion probes only, not writer adoption or recovery.
				other, err := policyevidencefs.OpenBundle(ctx, root, "11111111222233334444555555555555")
				if other != nil {
					_ = other.Close()
					return errors.New("duplicate runtime authority")
				}
				if !errors.Is(err, policyevidencefs.ErrBusy) {
					return errors.New("root lock not retained")
				}
				store, err := naspolicystore.Open(filepath.Join(root, "policy"))
				if store != nil {
					_ = store.Close()
					return errors.New("policy Store entered")
				}
				if !errors.Is(err, naspolicystore.ErrBusy) {
					return errors.New("actual policy lock not retained")
				}
				return nil
			})
		})
	}
}
