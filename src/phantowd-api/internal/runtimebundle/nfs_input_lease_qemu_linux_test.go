//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
)

func TestNFSInputsLeaseRefusesInvalidAuthority(t *testing.T) {
	candidate := nfsInputsCandidate(t, true, "127.0.0.1/32")
	for _, parent := range []*runtimebundle.NFSInputsQEMU{nil, {}} {
		if lease, err := runtimebundle.NewNFSInputLeaseQEMU(context.Background(), parent, candidate); err == nil || lease != nil {
			t.Fatal("invalid parent admitted")
		}
		if lease, err := runtimebundle.NewNFSInputLeaseQEMU(nil, parent, candidate); err == nil || lease != nil {
			t.Fatal("nil context admitted")
		}
	}
	for _, lease := range []*runtimebundle.NFSInputLeaseQEMU{nil, {}} {
		if lease.Check(context.Background()) == nil || lease.Close() == nil {
			t.Fatal("invalid lease admitted")
		}
	}
}

func TestNFSInputsLeaseRefusesSerializationAndPrivateFormatting(t *testing.T) {
	zero := runtimebundle.NFSInputLeaseQEMU{}
	if _, err := json.Marshal(zero); !errors.Is(err, runtimebundle.ErrInvalid) {
		t.Fatal("private lease serialized", err)
	}
	if err := json.Unmarshal([]byte(`{}`), &zero); !errors.Is(err, runtimebundle.ErrInvalid) {
		t.Fatal("private lease reconstructed", err)
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		if fmt.Sprintf(verb, zero) != "nfs-input-lease{private}" {
			t.Fatal("lease internals exposed")
		}
	}
}
