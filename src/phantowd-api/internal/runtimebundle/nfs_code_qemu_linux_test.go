//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"os"
	"testing"
)

func TestNFSCodeProbeRefusesBeforeCapture(t *testing.T) {
	data, expected, _ := nfsExpectedFixture(t)
	root, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, test := range []struct {
		name     string
		ctx      context.Context
		data     []byte
		expected [32]byte
		root     *os.File
		want     error
	}{
		{"context", nil, data, expected, root, ErrInvalid},
		{"root", context.Background(), data, expected, nil, ErrInvalid},
		{"canceled", canceled, data, expected, root, context.Canceled},
		{"document", context.Background(), nil, expected, root, ErrInvalid},
		{"expectation", context.Background(), data, [32]byte{}, root, ErrInvalid},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := ProbeNFSCodeQEMU(test.ctx, test.data, test.expected, test.root)
			if got != (Observation{}) || !errors.Is(err, test.want) {
				t.Fatal("refusal published evidence or lost its cause", err)
			}
			if _, err := root.Stat(); err != nil {
				t.Fatal("refusal closed the caller's root", err)
			}
		})
	}
}
