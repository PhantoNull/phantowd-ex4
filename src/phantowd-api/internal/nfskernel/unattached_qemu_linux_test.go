//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
package nfskernel

import (
	"context"
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

func TestUnattachedWitnessRefusesMissingOriginalController(t *testing.T) {
	for _, k := range []*ControllerQEMU{nil, {}} {
		for _, ctx := range []context.Context{nil, context.Background()} {
			if !errors.Is(k.CheckUnattachedStoppedQEMU(ctx), ErrRefused) {
				t.Fatal("invalid controller represented as settled")
			}
		}
	}
}

func TestUnattachedSocketObservationRequiresOriginalUnboundSocket(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	id, err := readNFSSocketIdentityQEMU(fd)
	if err != nil || checkUnattachedSocketQEMU(fd, id) != nil {
		t.Fatal("original unbound socket refused", err)
	}
	if checkUnattachedSocketQEMU(fd, nfsSocketIdentityQEMU{}) == nil {
		t.Fatal("missing identity admitted")
	}
	if err := unix.Bind(fd, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatal(err)
	}
	if checkUnattachedSocketQEMU(fd, id) == nil || !matchesNFSSocketIdentityQEMU(fd, id) {
		t.Fatal("bound socket admitted as unbound or observation changed identity")
	}
}
