//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
)

func pendingPlansFixture(t *testing.T) (*Plan, *Plan) {
	t.Helper()
	files := []File{exampleFile(pendingClientProgramQEMU), exampleFile("lib/ld-linux.so.3"), exampleFile("usr/lib/libsmbclient.so.0")}
	for name, value := range PendingClientDocumentsQEMU() {
		files = append(files, File{Path: name, Mode: 0444, Size: int64(len(value)), SHA256: sha256.Sum256([]byte(value))})
	}
	client, err := NewPlan(files, nil)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap, err := NewPlan([]File{exampleFile(pendingClientBootstrapQEMU)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return client, bootstrap
}

func TestPendingClientFixedPlansAndDocuments(t *testing.T) {
	client, bootstrap := pendingPlansFixture(t)
	if err := pendingClientPlansQEMU(client, bootstrap); err != nil {
		t.Fatal(err)
	}
	documents := PendingClientDocumentsQEMU()
	documents["etc/passwd"] = "changed"
	delete(documents, "etc/samba/smb.conf")
	if err := pendingClientPlansQEMU(client, bootstrap); err != nil || PendingClientDocumentsQEMU()["etc/passwd"] == "changed" {
		t.Fatal("fixed documents leaked mutable authority", err)
	}
	for index := range client.files {
		changed, _ := pendingPlansFixture(t)
		changed.files[index].SHA256[0] ^= 1
		if client.files[index].Mode == 0444 && pendingClientPlansQEMU(changed, bootstrap) == nil {
			t.Fatal("changed fixed document accepted", client.files[index].Path)
		}
	}
	for _, name := range []string{pendingClientProgramQEMU, "etc/passwd", "sys/firmware/devicetree/base/model", "lib/ld-linux.so.3", "usr/lib/libsmbclient.so.0"} {
		changed, _ := pendingPlansFixture(t)
		var files []File
		for _, file := range changed.files {
			if file.Path != name {
				files = append(files, file)
			}
		}
		changed.files = files
		if pendingClientPlansQEMU(changed, bootstrap) == nil {
			t.Fatal("missing original role accepted", name)
		}
	}
	var program *File
	for index := range client.files {
		if client.files[index].Path == pendingClientProgramQEMU {
			program = &client.files[index]
		}
	}
	for _, file := range []*File{program, &bootstrap.files[0]} {
		old := file.Mode
		file.Mode = 0755
		if pendingClientPlansQEMU(client, bootstrap) == nil {
			t.Fatal("old mutable executable mode accepted")
		}
		file.Mode = old
	}
}

func TestPendingClientInputsAbsentPartialCanceledOrReleasedRefuse(t *testing.T) {
	client, bootstrap := pendingPlansFixture(t)
	if value, err := newPendingClientInputsQEMU(context.Background(), client, bootstrap, nil, nil); value != nil || !errors.Is(err, ErrInvalid) {
		t.Fatal(value, err)
	}
	for _, inputs := range []*pendingClientInputsQEMU{nil, {}, {client: &retainedCode{}}, {client: &retainedCode{}, bootstrap: &retainedCode{}}} {
		if inputs.revalidate(context.Background()) == nil {
			t.Fatal("partial authority accepted")
		}
		if err := inputs.release(); err != nil {
			t.Fatal(err)
		}
		if inputs.revalidate(context.Background()) == nil {
			t.Fatal("released authority accepted")
		}
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	inputs := &pendingClientInputsQEMU{client: &retainedCode{}, bootstrap: &retainedCode{}}
	if !errors.Is(inputs.revalidate(canceled), context.Canceled) {
		t.Fatal("lost cancellation")
	}
	witness := errors.New("close uncertain")
	inputs.releaseErr = witness
	if inputs.release() != witness || inputs.revalidate(context.Background()) == nil {
		t.Fatal("uncertain release was retried/readmitted")
	}
}
