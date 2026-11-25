// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestReadTLSIdentityRetainsDescriptorOffset(t *testing.T) {
	cert, key := writeTestTLSFiles(t, "127.0.0.1")
	identity := writeTestTLSIdentity(t, cert, key)
	if _, err := identity.Seek(5, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	pair, err := readTLSIdentity(identity, uint32(os.Geteuid()))
	if err != nil || pair.PrivateKey == nil || len(pair.Certificate) != 1 {
		t.Fatalf("valid TLS identity was refused: %v", err)
	}
	if offset, err := identity.Seek(0, io.SeekCurrent); err != nil || offset != 5 {
		t.Fatalf("inherited file offset changed to %d: %v", offset, err)
	}
}

func TestReadTLSIdentityRejectsUnsafeInput(t *testing.T) {
	cert, key := writeTestTLSFiles(t, "127.0.0.1")
	_, anotherKey := writeTestTLSFiles(t, "127.0.0.1")
	owner := uint32(os.Geteuid())
	reject := func(t *testing.T, identity *os.File, owner uint32) {
		t.Helper()
		pair, err := readTLSIdentity(identity, owner)
		if !errors.Is(err, errTLSIdentity) || pair.PrivateKey != nil || len(pair.Certificate) != 0 {
			t.Fatalf("unsafe TLS identity accepted: %v", err)
		}
	}
	t.Run("mismatched key", func(t *testing.T) {
		reject(t, writeTestTLSIdentity(t, cert, anotherKey), owner)
	})
	t.Run("foreign owner", func(t *testing.T) {
		reject(t, writeTestTLSIdentity(t, cert, key), owner+1)
	})
	t.Run("group readable", func(t *testing.T) {
		identity := writeTestTLSIdentity(t, cert, key)
		if err := identity.Chmod(0640); err != nil {
			t.Fatal(err)
		}
		reject(t, identity, owner)
	})
	t.Run("multiply linked", func(t *testing.T) {
		identity := writeTestTLSIdentity(t, cert, key)
		if err := os.Link(identity.Name(), identity.Name()+".alias"); err != nil {
			t.Fatal(err)
		}
		reject(t, identity, owner)
	})
	t.Run("writable descriptor", func(t *testing.T) {
		identity := writeTestTLSIdentity(t, cert, key)
		writable, err := os.OpenFile(identity.Name(), os.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer writable.Close()
		reject(t, writable, owner)
	})
	t.Run("path descriptor", func(t *testing.T) {
		identity := writeTestTLSIdentity(t, cert, key)
		fd, err := unix.Open(identity.Name(), unix.O_PATH|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		pathOnly := os.NewFile(uintptr(fd), "path-only")
		defer pathOnly.Close()
		reject(t, pathOnly, owner)
	})
	t.Run("oversized bundle", func(t *testing.T) {
		identity := writeTestTLSIdentity(t, cert, key)
		if err := os.Truncate(identity.Name(), maxTLSIdentityBytes+1); err != nil {
			t.Fatal(err)
		}
		reject(t, identity, owner)
	})
	t.Run("pipe", func(t *testing.T) {
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer writer.Close()
		defer reader.Close()
		reject(t, reader, owner)
	})
}

func writeTestTLSIdentity(t *testing.T, cert, key string) *os.File {
	t.Helper()
	certificate, err := os.ReadFile(cert)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := os.ReadFile(key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "identity.pem")
	if err := os.WriteFile(path, append(certificate, privateKey...), 0600); err != nil {
		t.Fatal(err)
	}
	identity, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { identity.Close() })
	return identity
}
