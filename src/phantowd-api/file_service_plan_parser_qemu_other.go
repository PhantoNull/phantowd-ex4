//go:build qemu && !linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

// Native daemon parsers are exercised by the Linux ARMv5 QEMU integration
// fixture, not by host-side contract tests.
func validateQEMUPlanSambaWithTestparm(string) error { return nil }
