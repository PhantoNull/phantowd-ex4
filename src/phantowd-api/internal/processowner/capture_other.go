//go:build !linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"context"
	"os"
)

type CaptureOwner struct{}

func NewCapture(CaptureSpec, *os.File, *os.File) (*CaptureOwner, error) { return nil, ErrUnavailable }
func (*CaptureOwner) Capture(context.Context) (CaptureResult, error) {
	return CaptureResult{}, ErrUnavailable
}
func (*CaptureOwner) Settled(context.Context) (bool, error) { return false, ErrUnavailable }
func (*CaptureOwner) Close(context.Context) error           { return ErrUnavailable }
func (*CaptureOwner) MarshalJSON() ([]byte, error)          { return nil, ErrInvalid }
func (*CaptureOwner) UnmarshalJSON([]byte) error            { return ErrInvalid }
