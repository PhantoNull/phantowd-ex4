//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import "github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/backingpin"

func runQEMUWritableBackingConsumer() error { return backingpin.RunQEMUWritableConsumer() }
func runQEMUTargetBackingConsumer() error   { return backingpin.RunQEMUTargetConsumer() }
func runQEMULIOCredentialTest() error       { return backingpin.RunQEMULIOCredentialFixture() }
func runQEMULIOTargetTest() error           { return backingpin.RunQEMULIOTargetFixture() }
