//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package nfsowner_test

import (
	"context"
	"errors"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicystore"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/nfsowner"
)

func TestNFSLeasedSourceRuntimeMissingAndCanceledAuthority(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := nfsowner.NewLeasedSourceRuntimeQEMU(ctx, nil, nil, nil, nil, nil, 0); got != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled construction lost its cause", err)
	}
	if got, err := nfsowner.NewLeasedSourceRuntimeQEMU(nil, nil, nil, nil, nil, nil, 0); got != nil || !errors.Is(err, nfsowner.ErrInvalid) {
		t.Fatal("nil context admitted", err)
	}
	for missing := range 3 {
		policy, identity, storage := &naspolicystore.Lease{}, &identityowner.FileServiceLease{}, &mountowner.MountedVolumeSet{}
		switch missing {
		case 0:
			policy = nil
		case 1:
			identity = nil
		case 2:
			storage = nil
		}
		got, err := nfsowner.NewLeasedSourceRuntimeQEMU(context.Background(), nil, nil, policy, identity, storage, 0)
		if got != nil || !errors.Is(err, nfsowner.ErrInvalid) {
			t.Fatal("missing original authority admitted", err)
		}
	}
}
