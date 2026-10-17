//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policytransaction_test

import (
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/policytransaction"
)

func TestRuntimeHistoryAcrossCleanReboot(t *testing.T) {
	policytransaction.RunHistoryRebootFixture(t, runtimeHistoryProbe)
}
