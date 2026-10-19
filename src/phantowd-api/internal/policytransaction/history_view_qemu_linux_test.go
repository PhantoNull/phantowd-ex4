//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policytransaction

import (
	"context"
	"errors"
	"math"
	"strings"
	"sync"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsipolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/nfsconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

func TestHistoryViewDraftsRespectModelLimits(t *testing.T) {
	for _, block := range []uint16{512, 4096} {
		c, err := naspolicy.Decode(strings.NewReader(testPolicy))
		if err != nil {
			t.Fatal(err)
		}
		c.ISCSI.Backings[0].BlockSize = block
		c.ISCSI.Backings[0].CapacityBytes = uint64(math.MaxInt64) - uint64(block) + 1
		if c.Validate() != nil {
			t.Fatal("invalid boundary base")
		}
		files, err := draftViewFixture(c, 2, true)
		if err != nil {
			t.Fatal("invalid file-service fixture draft")
		}
		iscsi, err := draftViewFixture(files, 3, false)
		if err != nil || iscsi.ISCSI.Backings[0].CapacityBytes != c.ISCSI.Backings[0].CapacityBytes {
			t.Fatal("fixture changed or invalidated maximum backing capacity")
		}
		for _, view := range []bool{false, true} {
			if _, err := draftViewFixture(iscsi, 4, view); err != nil {
				t.Fatal("invalid concurrent fixture draft")
			}
		}
	}
}

func TestHistoryViewDraftsPreserveRetainedNFSBindings(t *testing.T) {
	base, err := naspolicy.Decode(strings.NewReader(testPolicy))
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range []struct {
		revision uint64
		files    bool
	}{{2, true}, {3, false}, {4, true}, {5, false}} {
		next, err := draftViewFixture(base, step.revision, step.files)
		if err != nil || fileservice.ValidateRetainedNFSBindings(base.FileServices, next.FileServices) != nil {
			t.Fatal("valid history-view fixture redirected a retained NFS identity", err)
		}
		if step.files && base.FileServices.NFS.Exports[0].Clients[0].Access == next.FileServices.NFS.Exports[0].Clients[0].Access {
			t.Fatal("fixture lost its nonempty NFS edit coverage")
		}
		base = next
	}
}

func TestHistoryViewEditsUseOriginalWriter(t *testing.T) {
	c, err := naspolicy.Decode(strings.NewReader(testPolicy))
	if err != nil {
		t.Fatal(err)
	}
	if err := exerciseHistoryViewEdits(context.Background(), c); errors.Is(err, ErrUnsupported) {
		t.Skip("unique mount identity unavailable; no positive writer qualification")
	} else if err != nil {
		t.Fatal(err)
	}
}

func TestHistoryViewDraftsRejectEmptyCollections(t *testing.T) {
	c, err := naspolicy.Decode(strings.NewReader(testPolicy))
	if err != nil {
		t.Fatal(err)
	}
	c.FileServices.Shares.Shares = []shareconfig.Share{}
	c.FileServices.NFS.Exports = []nfsconfig.Export{}
	c.ISCSI.Backings, c.ISCSI.Targets = []iscsipolicy.Backing{}, []iscsipolicy.Target{}
	if c.Validate() != nil {
		t.Fatal("invalid empty base")
	}
	for _, files := range []bool{false, true} {
		if got, err := draftViewFixture(c, 2, files); err != ErrInvalid || got.Revision != 0 {
			t.Fatal("empty fixture draft not refused")
		}
	}
}

func TestHistoryViewEditsRejectInvalidLifetimes(t *testing.T) {
	var absent *writer
	zero := &writer{}
	uninitialized := &writer{mu: &sync.Mutex{}}
	uninitialized.self = uninitialized
	copied := *uninitialized
	for _, w := range []*writer{absent, zero, uninitialized, &copied} {
		if got, err := w.executeFileServicesHistory(context.Background(), 1, fileservice.Config{}); err != ErrInvalid || got.revision != 0 {
			t.Fatal("invalid file-service lifetime admitted")
		}
		if got, err := w.executeISCSIHistory(context.Background(), 1, iscsipolicy.Policy{}); err != ErrInvalid || got.revision != 0 {
			t.Fatal("invalid iSCSI lifetime admitted")
		}
	}
}
