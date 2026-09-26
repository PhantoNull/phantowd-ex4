//go:build qemu && !linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import "errors"

func exerciseQEMUNFSIO() error { return errors.New("NFS I/O fixture requires Linux QEMU") }

func exerciseQEMUNFSMount(string) error { return errors.New("NFS mount fixture requires Linux QEMU") }
