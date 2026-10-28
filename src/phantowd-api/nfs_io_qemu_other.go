//go:build qemu && !linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import "errors"

func exerciseQEMUNFSIO() error { return errors.New("NFS I/O fixture requires Linux QEMU") }

func exerciseQEMUNFSMount(string) error { return errors.New("NFS mount fixture requires Linux QEMU") }

func probeQEMUUnmountedStorage() error {
	return errors.New("storage probe fixture requires Linux QEMU")
}

func runQEMUNFSKernelActivation() error { return errors.New("NFS kernel fixture requires Linux QEMU") }

func runQEMUNFSPeer(string) error { return errors.New("NFS peer fixture requires Linux QEMU") }

func runQEMUNFSOwnerActivation() error { return errors.New("NFS owner fixture requires Linux QEMU") }
