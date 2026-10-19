//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"context"
	"runtime"
	"testing"
)

func TestQEMUNFSKernelSocketTransactionIsExactAndBounded(t *testing.T) {
	for _, fd := range []int{0, 3, 17, 2147483647} {
		data, err := qemuNFSKernelPort(fd)
		if err != nil || len(data) == 0 || data[len(data)-1] != '\n' || len(data) > 11 {
			t.Fatal("valid socket descriptor refused", fd, err)
		}
		if fd == 17 && !bytes.Equal(data, []byte("17\n")) {
			t.Fatal("descriptor transaction changed")
		}
	}
	if data, err := qemuNFSKernelPort(-1); err == nil || data != nil {
		t.Fatal("invalid descriptor became a transaction")
	}
}

func TestQEMUNFSKernelControllerRefusesHostAndInvalidLifetimes(t *testing.T) {
	if runtime.GOARCH != "arm" {
		if k, err := openQEMUNFSKernel(context.Background()); err == nil || k != nil {
			t.Fatal("native host admitted to kernel controller")
		}
	}
	for _, k := range []*qemuNFSKernel{nil, {}} {
		for _, operation := range []func(context.Context) error{k.Start, k.Stop, k.Close} {
			if operation(nil) == nil || operation(context.Background()) == nil {
				t.Fatal("invalid controller was admitted")
			}
		}
	}
}
