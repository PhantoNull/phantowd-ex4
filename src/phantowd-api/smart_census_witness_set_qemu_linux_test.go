//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"io/fs"
	"testing"
)

func TestQEMUSMARTWitnessReaderPreservesCompleteLinkContract(t *testing.T) {
	reader := &qemuSMARTWitnessSetFS{base: fixtureDiscoverySysfs()}
	links, ok := any(reader).(fs.ReadLinkFS)
	if !ok {
		t.Fatal("configured reader erased the collector's ReadLinkFS contract")
	}
	if _, err := collectSMARTDiskCensus(context.Background(), reader); err != nil {
		t.Fatal("complete wrapped census refused", err)
	}
	if _, err := links.Lstat("class/block/sda"); err != nil {
		t.Fatal("configured reader did not delegate Lstat", err)
	}
	reader.fail = true
	if _, err := links.Lstat("class/block/sda"); !errors.Is(err, fs.ErrInvalid) {
		t.Fatal("injected reader failure bypassed Lstat", err)
	}
	if _, err := collectSMARTDiskCensus(context.Background(), reader); err == nil {
		t.Fatal("failed configured reader admitted a census")
	}
	reader.fail = false
	if _, err := collectSMARTDiskCensus(context.Background(), reader); err != nil {
		t.Fatal("restored fixture reader refused", err)
	}
}
