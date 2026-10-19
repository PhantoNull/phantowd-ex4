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

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/constructionreview"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/nfsowner"
)

func TestExportRootsRefuseMissingAuthorityWithoutPartialLifetime(t *testing.T) {
	candidate, _ := fixture(t, true)
	for _, lease := range []*mountowner.MountedVolumeSetLease{nil, {}} {
		roots, err := nfsowner.NewExportRootsQEMU(context.Background(), candidate, lease)
		if err == nil || roots != nil || constructionreview.Contains(err) {
			t.Fatal("missing authority returned a partial/retained lifetime", err)
		}
	}
	if roots, err := nfsowner.NewExportRootsQEMU(context.Background(), fileserviceplan.NFSv3Candidate{}, nil); !errors.Is(err, nfsowner.ErrInvalid) || roots != nil {
		t.Fatal("zero candidate accepted", err)
	}
	disabled, _ := fixture(t, false)
	if roots, err := nfsowner.NewExportRootsQEMU(context.Background(), disabled, nil); !errors.Is(err, nfsowner.ErrState) || roots != nil {
		t.Fatal("disabled policy captured source authority", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if roots, err := nfsowner.NewExportRootsQEMU(ctx, candidate, nil); !errors.Is(err, context.Canceled) || roots != nil {
		t.Fatal("canceled capture admitted", err)
	}
}

func TestExportRootsInvalidLifetimesAndSerializationRefuse(t *testing.T) {
	for _, roots := range []*nfsowner.ExportRootsQEMU{nil, {}} {
		if roots.Check(context.Background()) == nil || roots.Close() == nil {
			t.Fatal("invalid root lifetime accepted")
		}
	}
	zero := nfsowner.ExportRootsQEMU{}
	if _, err := json.Marshal(zero); !errors.Is(err, nfsowner.ErrPrivate) {
		t.Fatal("root lifetime serialized", err)
	}
	if err := json.Unmarshal([]byte(`{}`), &zero); !errors.Is(err, nfsowner.ErrPrivate) {
		t.Fatal("root lifetime deserialized", err)
	}
	if got := fmt.Sprintf("%#v", zero); got != "nfs-export-roots{private}" {
		t.Fatal("private source formatting changed")
	}
}
