// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"errors"
	"time"
)

const (
	MaxCaptureInput      = 64 << 10
	MaxCaptureStdout     = 64 << 10
	MaxCaptureStderr     = 4 << 10
	MaxCaptureExecutable = 16 << 20
)

var (
	ErrCaptureConsumed = errors.New("fixed capture already attempted")
	ErrCaptureOutput   = errors.New("fixed capture output refused")
	ErrCaptureResult   = errors.New("fixed capture result unavailable")
)

type CaptureExitKind uint8

const (
	CaptureUnknown CaptureExitKind = iota
	CaptureExited
	CaptureSignaled
)

// CaptureSpec is trusted construction input, never HTTP/RPC or per-operation
// input. ExecutableLabel is argv[0] only; the executable is a retained FD.
// RunAs has the same meaning as Spec: nil inherits the caller's credentials.
// This primitive does not qualify an isolated root, loader, hash or privilege
// profile. The first integration uses generic stdin replay, never a device.
type CaptureSpec struct {
	ExecutableLabel string
	Args            []string
	RunAs           *Credentials
	Timeout         time.Duration
	StopTimeout     time.Duration
}

// CaptureResult separates genuine ordinary exits from signal dispositions.
// Buffers are private raw data, not a public diagnostic or health assessment.
// Refused/canceled captures return an entirely zero result.
type CaptureResult struct {
	Kind           CaptureExitKind
	ExitCode       int
	Stdout, Stderr []byte
}

func (CaptureSpec) MarshalJSON() ([]byte, error) {
	return nil, ErrInvalid
}

func (*CaptureSpec) UnmarshalJSON([]byte) error    { return ErrInvalid }
func (CaptureResult) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
func (*CaptureResult) UnmarshalJSON([]byte) error  { return ErrInvalid }
