//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smbexec"
)

// This is the exact post-revocation call-site guard. Only the original exact
// changed-pair sentinel proves change: wrapping/joining it cannot erase an
// incomplete observation or turn it into successful revocation evidence.
func TestNativeRevokedPairObservationRequiresExactChangedSentinel(t *testing.T) {
	changed := smbexec.ErrNativeSessionPairChangedQEMU
	if err := requireNativeRevokedPairChangedQEMU(changed); err != nil {
		t.Fatal("complete changed observation refused", err)
	}
	if err := requireNativeRevokedPairChangedQEMU(nil); err == nil || !strings.Contains(err.Error(), "remained unchanged") {
		t.Error("unchanged pair lacks accurate refusal", err)
	}
	uncertain := errors.New("observation unavailable")
	for _, cause := range []error{context.DeadlineExceeded, context.Canceled, uncertain, fmt.Errorf("wrapped: %w", changed), errors.Join(changed, context.DeadlineExceeded)} {
		err := requireNativeRevokedPairChangedQEMU(cause)
		if err == nil || !errors.Is(err, cause) || !strings.Contains(err.Error(), "observation did not complete") || strings.Contains(err.Error(), "accepted") {
			t.Errorf("uncertain observation lost cause or became continuity: cause=%v result=%v", cause, err)
		}
	}
}
