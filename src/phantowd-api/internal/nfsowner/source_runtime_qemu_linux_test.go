//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package nfsowner_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/nfsowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
)

func TestSourceRuntimeRefusesMissingOriginalParents(t *testing.T) {
	for _, roots := range []*nfsowner.ExportRootsQEMU{nil, {}} {
		for _, inputs := range []*runtimebundle.NFSInputsQEMU{nil, {}} {
			if value, err := nfsowner.NewSourceRuntimeQEMU(context.Background(), roots, inputs); value != nil || err == nil {
				t.Fatal("missing original parents admitted")
			}
		}
	}
}

func TestSourceRuntimePrivateHandlesAndCanceledConstruction(t *testing.T) {
	for _, value := range []*nfsowner.SourceRuntimeQEMU{nil, {}} {
		if value.Check(context.Background()) == nil || value.Close() == nil {
			t.Fatal("invalid join handle admitted")
		}
	}
	zero := nfsowner.SourceRuntimeQEMU{}
	if _, err := json.Marshal(zero); !errors.Is(err, nfsowner.ErrPrivate) {
		t.Fatal("private join serialized")
	}
	if err := json.Unmarshal([]byte(`{}`), &zero); !errors.Is(err, nfsowner.ErrPrivate) || fmt.Sprintf("%#v", zero) != "nfs-source-runtime{private}" {
		t.Fatal("private join reconstructed or formatted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if value, err := nfsowner.NewSourceRuntimeQEMU(ctx, nil, nil); value != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("pre-canceled construction admitted")
	}
	if value, err := nfsowner.NewSourceRuntimeQEMU(nil, nil, nil); value != nil || !errors.Is(err, nfsowner.ErrInvalid) {
		t.Fatal("nil context admitted")
	}
}
