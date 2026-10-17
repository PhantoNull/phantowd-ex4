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

func TestRuntimeHistoryObserverAfterProcessLoss(t *testing.T) {
	for _, stage := range policytransaction.RuntimeHistoryLossStages() {
		t.Run(stage, func(t *testing.T) { policytransaction.RunRuntimeHistoryLossFixture(t, stage, runtimeHistoryProbe) })
	}
}

func runtimeHistoryProbe(ctx context.Context, root string, checkpoint []byte, pending bool, want policyevidence.Kind) (result error) {
	a, err := policyevidencefs.OpenHistory(ctx, root, "11111111222233334444555555555555", checkpoint)
	if err != nil {
		return errors.New("runtime history open refused")
	}
	defer func() {
		if a.Close() != nil {
			result = errors.New("runtime history close uncertain")
		}
	}()
	for range 2 {
		d, err := a.Observe(ctx)
		if pending {
			if !errors.Is(err, policyevidencefs.ErrReview) || d.Kind() != "" {
				return errors.New("pending history became diagnosis")
			}
		} else if err != nil || d.Kind() != want {
			return errors.New("incorrect runtime history diagnosis")
		}
	}
	other, err := policyevidencefs.OpenHistory(ctx, root, "11111111222233334444555555555555", checkpoint)
	if other != nil {
		_ = other.Close()
		return errors.New("duplicate history authority")
	}
	if !errors.Is(err, policyevidencefs.ErrBusy) {
		return errors.New("history root lock not retained")
	}
	store, err := naspolicystore.Open(filepath.Join(root, "policy"))
	if store != nil {
		_ = store.Close()
		return errors.New("history policy Store entered")
	}
	if !errors.Is(err, naspolicystore.ErrBusy) {
		return errors.New("history policy lock not retained")
	}
	return nil
}
