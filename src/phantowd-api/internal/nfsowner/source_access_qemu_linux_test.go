//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package nfsowner_test

import (
	"context"
	"errors"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/nfsowner"
)

func TestSourceRuntimeServerOwnerRefusesInvalidOriginalLifetime(t *testing.T) {
	for _, value := range []*nfsowner.SourceRuntimeQEMU{nil, {}} {
		for _, ctx := range []context.Context{nil, context.Background()} {
			if owner, err := value.NewServerOwnerFixtureQEMU(ctx); owner != nil || !errors.Is(err, nfsowner.ErrInvalid) {
				t.Fatal("invalid original source admitted a server Owner", err)
			}
		}
	}
}

func TestSourceRuntimeServerOwnerAccessAndRetainedStopRefuseInvalidLifetime(t *testing.T) {
	for _, owner := range []*nfsowner.Owner{nil, {}} {
		if owner.InjectSourceMountdExitFixtureQEMU(context.Background()) == nil {
			t.Fatal("invalid Owner admitted an independent mountd exit")
		}
		if owner.ExerciseSourceIOFixtureQEMU(context.Background()) == nil {
			t.Fatal("invalid Owner admitted fixed source I/O")
		}
	}
	for _, source := range []*nfsowner.SourceRuntimeQEMU{nil, {}} {
		if source.VerifyServerStoppedRetainedFixtureQEMU(context.Background()) == nil {
			t.Fatal("invalid source admitted retained stopped proof")
		}
	}
}

func TestSourceRuntimeAccessRefusesInvalidHandles(t *testing.T) {
	for _, value := range []*nfsowner.SourceRuntimeQEMU{nil, {}} {
		if value.RunAccessFixtureQEMU(context.Background()) == nil {
			t.Fatal("invalid source/input join started NFS access")
		}
	}
}

func TestSourceRuntimeLossProbeRefusesInvalidHandles(t *testing.T) {
	for _, value := range []*nfsowner.SourceRuntimeQEMU{nil, {}} {
		if value.ProbeSourceLossFixtureQEMU(context.Background()) == nil {
			t.Fatal("invalid source/input join accepted a live-loss proof")
		}
		if value.ProbeSourceDaemonLossFixtureQEMU(context.Background()) == nil || value.InjectSourceMountdExitFixtureQEMU(context.Background()) == nil {
			t.Fatal("invalid source runtime admitted combined fault")
		}
	}
}

func TestSourceRuntimeWithdrawalRefusesInvalidHandles(t *testing.T) {
	for _, value := range []*nfsowner.SourceRuntimeQEMU{nil, {}} {
		if value.WithdrawSourceLossFixtureQEMU(context.Background()) == nil {
			t.Fatal("invalid source owner admitted withdrawal")
		}
	}
}
