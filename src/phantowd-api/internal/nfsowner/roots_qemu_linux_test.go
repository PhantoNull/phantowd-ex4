//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package nfsowner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/constructionreview"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
)

func TestExportRootsRefuseMissingAuthorityWithoutPartialLifetime(t *testing.T) {
	candidate, _ := lifetimeInputs(t, true)
	if roots, err := NewExportRootsQEMU(nil, candidate, nil); roots != nil || err != ErrInvalid {
		t.Fatal("nil context admitted", err)
	}
	for _, lease := range []*mountowner.MountedVolumeSetLease{nil, {}} {
		roots, err := NewExportRootsQEMU(context.Background(), candidate, lease)
		if err == nil || roots != nil || constructionreview.Contains(err) {
			t.Fatal("missing authority returned a partial/retained lifetime", err)
		}
	}
	if roots, err := NewExportRootsQEMU(context.Background(), fileserviceplan.NFSv3Candidate{}, nil); !errors.Is(err, ErrInvalid) || roots != nil {
		t.Fatal("zero candidate accepted", err)
	}
	disabled, _ := lifetimeInputs(t, false)
	if roots, err := NewExportRootsQEMU(context.Background(), disabled, nil); !errors.Is(err, ErrState) || roots != nil {
		t.Fatal("disabled policy captured source authority", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if roots, err := NewExportRootsQEMU(ctx, candidate, nil); !errors.Is(err, context.Canceled) || roots != nil {
		t.Fatal("canceled capture admitted", err)
	}
}

func TestExportRootsInvalidLifetimesAndSerializationRefuse(t *testing.T) {
	for _, roots := range []*ExportRootsQEMU{nil, {}} {
		if roots.Check(context.Background()) == nil || roots.Close() == nil {
			t.Fatal("invalid root lifetime accepted")
		}
	}
	zero := ExportRootsQEMU{}
	if _, err := json.Marshal(zero); !errors.Is(err, ErrPrivate) {
		t.Fatal("root lifetime serialized", err)
	}
	if err := json.Unmarshal([]byte(`{}`), &zero); !errors.Is(err, ErrPrivate) {
		t.Fatal("root lifetime deserialized", err)
	}
	if got := fmt.Sprintf("%#v", zero); got != "nfs-export-roots{private}" {
		t.Fatal("private source formatting changed")
	}
}

// Wrong access flags refuse before statx support is relevant on the native host.
func TestExportRootObservationRejectsOrdinaryAndClosedDescriptors(t *testing.T) {
	directory, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	closed, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	for _, file := range []*os.File{nil, directory, closed} {
		if _, err := observeExportRoot(file, fileserviceplan.VolumeBinding{}); !errors.Is(err, ErrReviewRequired) {
			t.Fatal("ordinary, closed or absent descriptor admitted", err)
		}
	}
	if _, err := directory.Stat(); err != nil {
		t.Fatal("observation consumed the caller's original directory", err)
	}
}

// Model-only guard: this does not inject a real kernel close failure.
func TestExportRootsUncertainFlagRetainsRemainingReferences(t *testing.T) {
	file, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	owner := &ExportRootsQEMU{}
	owner.inner = &exportRoots{original: owner, gate: make(chan struct{}, 1), closeUncertain: true, roots: []exportRoot{{file: file}}}
	copy := *owner
	if copy.Check(context.Background()) != ErrInvalid || copy.Close() != ErrInvalid {
		t.Fatal("copied model lifetime admitted")
	}
	for range 2 {
		if err := owner.Close(); !errors.Is(err, ErrReviewRequired) {
			t.Fatal("uncertain closure was retried", err)
		}
	}
	if _, err := file.Stat(); err != nil || owner.inner.roots[0].file != file {
		t.Fatal("uncertain closure released an original reference", err)
	}
}
