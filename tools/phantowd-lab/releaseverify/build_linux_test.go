//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package releaseverify

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestBuildUnsignedManifestLinuxRejectsFIFOAndDirectorySymlink(t *testing.T) {
	spec, payloads, dir, key := unsignedBuildFixture(t)
	name := filepath.Join(dir, "z-rootfs.test")
	if err := os.Remove(name); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(name, 0600); err != nil {
		t.Fatal(err)
	}
	if data, err := BuildUnsignedManifest(spec, payloads, dir, key.Public().(ed25519.PublicKey)); err == nil || data != nil {
		t.Fatal("FIFO admitted")
	}
	link := filepath.Join(t.TempDir(), "payloads")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if data, err := BuildUnsignedManifest(spec, payloads, link, key.Public().(ed25519.PublicKey)); err == nil || data != nil {
		t.Fatal("symlink directory admitted")
	}
}

func TestBuildUnsignedManifestLinuxPreflightsWholeSizeBeforeRead(t *testing.T) {
	spec, _, dir, key := unsignedBuildFixture(t)
	var payloads []PayloadSpec
	for _, name := range []string{"one.test", "two.test", "three.test"} {
		file, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		// Sparse tmpfs files: no GiB of data is allocated or written.
		truncateErr := file.Truncate(maxArtifactSize)
		closeErr := file.Close()
		if truncateErr != nil || closeErr != nil {
			t.Fatal(truncateErr, closeErr)
		}
		payloads = append(payloads, PayloadSpec{Name: name, Role: "test-payload"})
	}
	watch, err := syscall.InotifyInit1(syscall.IN_NONBLOCK | syscall.IN_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(watch)
	if _, err := syscall.InotifyAddWatch(watch, dir, syscall.IN_OPEN|syscall.IN_ACCESS); err != nil {
		t.Fatal(err)
	}
	if data, err := BuildUnsignedManifest(spec, payloads, dir, key.Public().(ed25519.PublicKey)); err == nil || data != nil {
		t.Fatal("over-budget whole set emitted a manifest")
	}
	var events [1024]byte
	if _, err := syscall.Read(watch, events[:]); !errors.Is(err, syscall.EAGAIN) {
		t.Fatal("over-budget preflight opened or read a payload", err)
	}
	// Verify the actual open/read observer, independent of filesystem atime.
	file, err := os.Open(filepath.Join(dir, "one.test"))
	if err != nil {
		t.Fatal(err)
	}
	var byteOnly [1]byte
	_, readErr := file.Read(byteOnly[:])
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		t.Fatal(readErr, closeErr)
	}
	if count, err := syscall.Read(watch, events[:]); err != nil || count <= 0 {
		t.Fatal("open/read observation control unavailable", err)
	}
}
