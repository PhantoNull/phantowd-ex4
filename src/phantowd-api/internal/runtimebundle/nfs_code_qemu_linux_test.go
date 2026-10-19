//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
)

func TestNFSCodeRefusesHostBeforeConsumingCallerRoot(t *testing.T) {
	if runtime.GOARCH == "arm" {
		t.Skip("host-refusal contract; positive ARM proof uses explicit isolated fixture")
	}
	root, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	code, err := runtimebundle.NewNFSCodeQEMU(context.Background(), nfsExpectedJSON(t, nfsExpectedFixture(t)), root)
	if code != nil || !errors.Is(err, runtimebundle.ErrInvalid) {
		t.Fatal("host admitted code lifetime", err)
	}
	if _, err := root.Stat(); err != nil {
		t.Fatal("host refusal consumed caller root")
	}
}

func TestNFSCodeInvalidCanceledAndPrivateHandles(t *testing.T) {
	for _, value := range []*runtimebundle.NFSCodeQEMU{nil, {}} {
		if value.Check(context.Background()) == nil || value.Close() == nil {
			t.Fatal("invalid code handle accepted")
		}
	}
	zero := runtimebundle.NFSCodeQEMU{}
	if _, err := json.Marshal(zero); !errors.Is(err, runtimebundle.ErrInvalid) {
		t.Fatal("code lifetime serialized", err)
	}
	if err := json.Unmarshal([]byte(`{}`), &zero); !errors.Is(err, runtimebundle.ErrInvalid) {
		t.Fatal("code lifetime deserialized", err)
	}
	if fmt.Sprintf("%#v", zero) != "nfs-code{private}" {
		t.Fatal("code lifetime leaked private representation")
	}
	root, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if code, err := runtimebundle.NewNFSCodeQEMU(ctx, nfsExpectedJSON(t, nfsExpectedFixture(t)), root); code != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled constructor admitted/consumed inputs", err)
	}
}
