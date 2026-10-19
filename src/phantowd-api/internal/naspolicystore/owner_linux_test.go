//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package naspolicystore

import (
	"context"
	"errors"
	"os"
	"reflect"
	"testing"
)

func TestNASOwnerBindingRefusalPreservesAdmissionAndPermitsValidSuccessor(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(0, nfsBindingPolicy(1)); err != nil {
		store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	owner, err := OpenOwner(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	ctx := context.Background()
	next := nfsBindingPolicy(2)
	next.FileServices.NFS.Exports[0].RelativePath = "unrelated"
	if err := owner.Commit(ctx, 1, next); !errors.Is(err, ErrInvalid) {
		t.Fatal("owner published a rebound NFS identity", err)
	}
	lease, err := owner.Acquire(ctx, 1)
	if err != nil {
		t.Fatal("pure refusal quarantined unchanged policy", err)
	}
	defer lease.Release()
	if got, err := lease.Snapshot(ctx); err != nil || !reflect.DeepEqual(got, nfsBindingPolicy(1)) {
		t.Fatal("binding refusal changed retained policy", err)
	}
	if err := lease.Release(); err != nil {
		t.Fatal(err)
	}
	next = nfsBindingPolicy(2)
	next.FileServices.NFS.Exports[0].Clients[0].Access = "rw"
	if err := owner.Commit(ctx, 1, next); err != nil {
		t.Fatal("valid access-only successor refused", err)
	}
}

func TestNASOwnerFencesAllProtocolRevisionsTogether(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Commit(0, emptyPolicy(1)); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	o, err := OpenOwner(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	ctx := context.Background()
	lease, err := o.Acquire(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	got, err := lease.Snapshot(ctx)
	if err != nil || !reflect.DeepEqual(got, emptyPolicy(1)) {
		t.Fatal("incoherent lease", got, err)
	}
	if err := o.Commit(ctx, 1, emptyPolicy(2)); !errors.Is(err, ErrBusy) {
		t.Fatal("lease did not fence", err)
	}
	if err := lease.Release(); err != nil {
		t.Fatal(err)
	}
	mixed := emptyPolicy(2)
	mixed.ISCSI.VolumeRevision = 1
	if err := o.Commit(ctx, 1, mixed); !errors.Is(err, ErrInvalid) {
		t.Fatal("mixed binding", err)
	}
	if err := o.Commit(ctx, 1, emptyPolicy(2)); err != nil {
		t.Fatal(err)
	}
	got, err = o.Snapshot(ctx)
	if err != nil || !reflect.DeepEqual(got, emptyPolicy(2)) {
		t.Fatal("split publication", got, err)
	}
}
