// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package naspolicystore

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/nfsconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

func TestNASStoreAndOwnerRejectRetainedNFSRootChange(t *testing.T) {
	check := func(got, want error) {
		t.Helper()
		if !errors.Is(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	policy := func(revision uint64) naspolicy.Config {
		c := emptyPolicy(revision)
		c.FileServices.Shares.Volumes = []shareconfig.Volume{{ID: "bulk", FilesystemUUID: "11111111-2222-3333-4444-555555555555"}}
		c.FileServices.NFS.Exports = []nfsconfig.Export{{ID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", VolumeID: "bulk", RelativePath: "books", Clients: []nfsconfig.Client{{Network: "192.0.2.10/32", Access: "ro", Squash: "all", AnonymousUID: 65534, AnonymousGID: 65534, Security: "sys"}}}}
		return c
	}
	dir := t.TempDir()
	check(os.Chmod(dir, 0700), nil)
	s, err := Open(dir)
	check(err, nil)
	defer s.Close()
	check(s.Commit(0, policy(1)), nil)
	read := func() []byte {
		data, err := os.ReadFile(filepath.Join(dir, "nas-services.json"))
		check(err, nil)
		return data
	}
	before := read()
	bad := policy(2)
	bad.FileServices.NFS.Exports[0].RelativePath = "other"
	check(s.Commit(1, bad), ErrInvalid)
	if !bytes.Equal(before, read()) {
		t.Fatal("store rejection altered current bytes")
	}
	check(s.Close(), nil)
	o, err := OpenOwner(dir)
	check(err, nil)
	defer o.Close()
	ctx := context.Background()
	lease, err := o.Acquire(ctx, 1)
	check(err, nil)
	defer lease.Release()
	check(o.Commit(ctx, 1, bad), ErrBusy)
	check(lease.Release(), nil)
	check(o.Commit(ctx, 1, bad), ErrInvalid)
	if !bytes.Equal(before, read()) {
		t.Fatal("owner rejection altered current bytes")
	}
	lease, err = o.Acquire(ctx, 1)
	check(err, nil)
	defer lease.Release()
	if got, err := lease.Snapshot(ctx); err != nil || !reflect.DeepEqual(got, policy(1)) {
		t.Fatal("rejection changed or quarantined retained policy", err)
	}
	check(lease.Release(), nil)
	next := policy(2)
	next.FileServices.NFS.Exports[0].Clients[0].Access = "rw"
	check(o.Commit(ctx, 1, next), nil)
	if got, err := o.Snapshot(ctx); err != nil || !reflect.DeepEqual(got, next) {
		t.Fatal("client access change was not published", err)
	}
}
