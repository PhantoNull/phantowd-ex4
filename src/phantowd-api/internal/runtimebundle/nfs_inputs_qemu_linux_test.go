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

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
)

func TestNFSInputsRefuseHostWithoutConsumingRoots(t *testing.T) {
	if runtime.GOARCH == "arm" {
		t.Skip("positive proof requires isolated disposable ARM fixture")
	}
	root, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	inputs, err := runtimebundle.NewNFSInputsQEMU(context.Background(), nfsExpectedJSON(t, nfsExpectedFixture(t)),
		nfsInputsCandidate(t, true, "127.0.0.1/32"), root, root, root)
	if inputs != nil || !errors.Is(err, runtimebundle.ErrInvalid) {
		t.Fatal("host gained NFS input lifetime", err)
	}
	if _, err := root.Stat(); err != nil {
		t.Fatal("host refusal consumed original caller root")
	}
}

func TestNFSInputsInvalidCanceledAndPrivateHandles(t *testing.T) {
	for _, value := range []*runtimebundle.NFSInputsQEMU{nil, {}} {
		if value.Check(context.Background()) == nil || value.Close() == nil {
			t.Fatal("invalid NFS inputs lifetime accepted")
		}
	}
	zero := runtimebundle.NFSInputsQEMU{}
	if _, err := json.Marshal(zero); !errors.Is(err, runtimebundle.ErrInvalid) {
		t.Fatal("private inputs serialized", err)
	}
	if err := json.Unmarshal([]byte(`{}`), &zero); !errors.Is(err, runtimebundle.ErrInvalid) || fmt.Sprintf("%#v", zero) != "nfs-inputs{private}" {
		t.Fatal("private inputs reconstructed or formatted")
	}
	root, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if value, err := runtimebundle.NewNFSInputsQEMU(ctx, nil, fileserviceplan.NFSv3Candidate{}, root, root, root); value != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("pre-canceled capture had effects", err)
	}
}
