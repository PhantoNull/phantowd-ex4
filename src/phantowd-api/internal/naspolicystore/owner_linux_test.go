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
