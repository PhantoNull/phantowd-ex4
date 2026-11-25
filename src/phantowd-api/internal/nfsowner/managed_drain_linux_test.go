// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package nfsowner

import (
	"context"
	"errors"
	"testing"
)

func TestManagedStopRequiresDrainBeforeChangingRuntime(t *testing.T) {
	undrained := errors.New("client drain unconfirmed")
	// There is no kernel or export handle to touch in this refusal case.
	m := &managedLinux{
		kernelAttempted: true,
		exportAttempted: true,
		quiescent:       func(context.Context) error { return undrained },
	}
	if err := m.Stop(context.Background()); !errors.Is(err, undrained) {
		t.Fatalf("stop reached runtime without drain proof: %v", err)
	}
	if err := m.VerifyStopped(context.Background()); !errors.Is(err, undrained) {
		t.Fatalf("stopped verification treated the lifetime as drained: %v", err)
	}
}
