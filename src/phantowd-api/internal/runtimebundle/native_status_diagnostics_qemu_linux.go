//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"crypto/sha256"
	"errors"
	"strings"
)

// Classification only: the actual completion seam constructs this after zero
// exit/exactly one handoff/verified settlement+post-admission and extra stderr.
// No producer bytes, path, account, process or authority enter the cause.
type nativeStatusDiagnosticRefusalQEMU struct {
	diagnosticBytes  int
	diagnosticSHA256 [sha256.Size]byte
}

func newNativeStatusDiagnosticRefusalQEMU(stderr []byte) *nativeStatusDiagnosticRefusalQEMU {
	// Only the digest/size survive. The caller already proved exactly one
	// fixed handoff, and capture bounds the original stream. Never retain it.
	index := strings.Index(string(stderr), nativeCredentialHandoff)
	hash := sha256.New()
	_, _ = hash.Write(stderr[:index])
	_, _ = hash.Write(stderr[index+len(nativeCredentialHandoff):])
	refusal := &nativeStatusDiagnosticRefusalQEMU{diagnosticBytes: len(stderr) - len(nativeCredentialHandoff)}
	copy(refusal.diagnosticSHA256[:], hash.Sum(nil))
	return refusal
}

func (*nativeStatusDiagnosticRefusalQEMU) Error() string {
	return "native status diagnostic stream refused"
}
func (*nativeStatusDiagnosticRefusalQEMU) Unwrap() error { return ErrMismatch }

// NativeStatusDiagnosticsRefusedQEMU is read-only diagnostic classification,
// not a source-completeness or admission witness. Text/other failures cannot
// manufacture it; the first worker failure in the supplied chain must match.
func NativeStatusDiagnosticsRefusedQEMU(err error) bool {
	var worker *nativeWorkerErrorQEMU
	var refusal *nativeStatusDiagnosticRefusalQEMU
	return errors.As(err, &worker) && worker != nil && worker.stage == nativeWorkerResultQEMU &&
		errors.As(worker.cause, &refusal) && refusal != nil
}
