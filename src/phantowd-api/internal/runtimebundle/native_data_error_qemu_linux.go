//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"errors"
	"fmt"
)

// Private error witness; underlying output, paths and credentials never format.
// Unlike a worker review error, this wrapper preserves the original semantics:
// the containing runtime/coordinator remains responsible for quarantine.
type nativeDataErrorQEMU struct {
	operation string
	stage     nativeWorkerStageQEMU
	cause     error
}

func nativeDataFailureQEMU(operation string, stage nativeWorkerStageQEMU, cause error) error {
	if cause == nil {
		cause = ErrUnavailable
	}
	return &nativeDataErrorQEMU{operation: operation, stage: stage, cause: cause}
}

func (e *nativeDataErrorQEMU) Error() string {
	got := ObserveNativeDataFailureQEMU(e)
	return fmt.Sprintf("native data operation=%s phase=%s reason=%s", got.Operation, got.Phase, got.Reason)
}

func (e *nativeDataErrorQEMU) Unwrap() error { return e.cause }

type NativeDataFailureObservationQEMU struct {
	Present                  bool
	Operation, Phase, Reason string
}

// Diagnostic-only classification from the first typed failure in an error
// tree. No state, command, admission or cleanup operation is performed.
func ObserveNativeDataFailureQEMU(err error) NativeDataFailureObservationQEMU {
	var failure *nativeDataErrorQEMU
	if !errors.As(err, &failure) || failure == nil {
		return NativeDataFailureObservationQEMU{}
	}
	operation := "unknown"
	switch failure.operation {
	case "rw-write", "rw-read", "ro-read", "ro-write", "escape", "ungranted", "unix-owner", "kernel-ro", "transfer", "denial", "final-daemon":
		operation = failure.operation
	}
	phase, reason := (&nativeWorkerErrorQEMU{stage: failure.stage, cause: failure.cause}).labels()
	return NativeDataFailureObservationQEMU{Present: true, Operation: operation, Phase: phase, Reason: reason}
}
