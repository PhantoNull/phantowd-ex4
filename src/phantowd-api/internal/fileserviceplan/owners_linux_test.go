//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package fileserviceplan

import (
	"context"
	"errors"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
)

func TestBuildFromOwnersRefusesMissingTrustedOwners(t *testing.T) {
	if _, err := BuildFromOwners(context.Background(), fileservice.Config{}, 0, nil, nil); !errors.Is(err, ErrNotReady) {
		t.Fatalf("missing identity and storage Owners must fail closed: %v", err)
	}
}
