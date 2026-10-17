//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package smbexec

// EmptyNativeStatusDiagnosticQEMU classifies bytes with the ORIGINAL bounded
// status decoder. It grants no absence/completeness or execution authority:
// the source-fault fixture deliberately shows why valid JSON is insufficient.
func EmptyNativeStatusDiagnosticQEMU(output []byte) bool {
	sessions, err := nativeSessionsQEMU(output)
	return err == nil && len(sessions) == 0
}
