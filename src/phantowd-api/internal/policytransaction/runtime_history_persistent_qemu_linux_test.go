//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policytransaction_test

import (
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/policytransaction"
)

func TestRuntimeHistoryObserverAfterExt4ProcessLoss(t *testing.T) {
	for _, stage := range policytransaction.RuntimeHistoryLossStages() {
		t.Run(stage, func(t *testing.T) { policytransaction.RunRuntimeHistoryExt4LossFixture(t, stage, runtimeHistoryProbe) })
	}
}
