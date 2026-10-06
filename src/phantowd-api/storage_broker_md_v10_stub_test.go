//go:build !qemu || !linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"testing"
)

func TestMDV10BrokerProviderIsUnavailableOutsideLinuxQEMU(t *testing.T) {
	if _, err := observeTrustedMDV10ForBroker(context.Background()); !errors.Is(err, errStorageBrokerUnavailable) {
		t.Fatal("non-QEMU production provider must refuse the MD scan without opening storage")
	}
}
