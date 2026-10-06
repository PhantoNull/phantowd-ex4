//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"slices"
	"testing"

	"golang.org/x/sys/unix"
)

func TestConfigurationPlanKeepsProtectedModesDistinctFromCode(t *testing.T) {
	data := []byte("[global]\nmap to guest = Never\n")
	input := File{Path: "samba/smb.conf", SHA256: sha256.Sum256(data), Size: int64(len(data)), Mode: 0600}
	if _, err := NewPlan([]File{input}, nil); err == nil {
		t.Fatal("code admission must not accept writable protected configuration modes")
	}
	configuration, err := newConfigurationPlan([]File{input})
	if err != nil || configuration == nil {
		t.Fatal("separate protected configuration was refused", err)
	}
	if configuration.plan.files[0] != input || configuration.plan.nodes["samba"] != 'd' {
		t.Fatal("protected configuration contract was not preserved")
	}
}

func TestConfigurationPlanRefusesExecutableAmbiguousOrUnboundedInputs(t *testing.T) {
	valid := File{Path: "samba/smb.conf", SHA256: sha256.Sum256([]byte("trusted")), Size: 7, Mode: 0600}
	for _, mode := range []uint32{0, 0555, 0755, 0660, 0666, 04600} {
		bad := valid
		bad.Mode = mode
		if _, err := newConfigurationPlan([]File{bad}); err == nil {
			t.Fatal("unsafe configuration mode accepted", mode)
		}
	}
	for _, size := range []int64{-1, 0, maxConfigurationBytes + 1} {
		bad := valid
		bad.Size = size
		if _, err := newConfigurationPlan([]File{bad}); err == nil {
			t.Fatal("unbounded configuration accepted", size)
		}
	}
	for _, name := range []string{".", "../passwd", "/passwd", "samba//smb.conf"} {
		bad := valid
		bad.Path = name
		if _, err := newConfigurationPlan([]File{bad}); err == nil {
			t.Fatal("ambiguous configuration path accepted", name)
		}
	}
	for _, inputs := range [][]File{nil, {valid, valid}, slices.Repeat([]File{valid}, 17)} {
		if _, err := newConfigurationPlan(inputs); err == nil {
			t.Fatal("invalid configuration roster accepted")
		}
	}
	maximum := valid
	maximum.Size = maxConfigurationBytes
	if _, err := newConfigurationPlan([]File{maximum}); err != nil {
		t.Fatal("bounded maximum refused", err)
	}
	other := valid
	other.Path = "passwd"
	if _, err := newConfigurationPlan([]File{maximum, other}); err == nil {
		t.Fatal("aggregate configuration byte bound bypassed")
	}
}

func TestConfigurationPlanCopiesTrustedInputs(t *testing.T) {
	inputs := []File{{Path: "passwd", SHA256: sha256.Sum256([]byte("trusted")), Size: 7, Mode: 0644}}
	configuration, err := newConfigurationPlan(inputs)
	if err != nil {
		t.Fatal(err)
	}
	original := inputs[0]
	inputs[0].Path = "replacement"
	inputs[0].Mode = 0755
	if configuration.plan.files[0] != original {
		t.Fatal("caller replaced immutable configuration inputs")
	}
}

func TestConfigurationRetentionRefusesWritableRootAndCancellationWithoutConsumingCaller(t *testing.T) {
	data := []byte("files-only-nss\n")
	configuration, err := newConfigurationPlan([]File{{Path: "nsswitch.conf", SHA256: sha256.Sum256(data), Size: int64(len(data)), Mode: 0644}})
	if err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(t.TempDir(), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	root := os.NewFile(uintptr(fd), "caller-config-root")
	defer root.Close()
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if retained, err := configuration.retain(canceled, root); retained != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled config admission had effects", retained, err)
	}
	if retained, err := configuration.retain(context.Background(), root); retained != nil || !errors.Is(err, ErrMismatch) {
		t.Fatal("writable configuration root admitted", retained, err)
	}
	if _, err := root.Stat(); err != nil {
		t.Fatal("refusal consumed caller root", err)
	}
}
