//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policytransaction_test

import (
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/policytransaction"
)

func TestRuntimeHistoryWriterOnExt4(t *testing.T) {
	policytransaction.RunHistoryWriterMediaFixture(t, runtimeHistoryProbe)
}

func TestHistoryMediaObservationChild(t *testing.T) {
	policytransaction.RunHistoryMediaObservationChild(t, runtimeHistoryProbe)
}
