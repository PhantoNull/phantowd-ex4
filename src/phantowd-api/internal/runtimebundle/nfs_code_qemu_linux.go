//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"os"
)

// ProbeNFSCodeQEMU is a disposable data-only fixture, not a service constructor.
// It returns no retained descriptors, executable authority or storage grant.
func ProbeNFSCodeQEMU(ctx context.Context, data []byte, expected [32]byte, root *os.File) (observation Observation, result error) {
	if ctx == nil || root == nil {
		return Observation{}, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return Observation{}, err
	}
	plan, err := DecodeNFSExpectedQEMU(data, expected)
	if err != nil {
		return Observation{}, err
	}
	model, err := os.ReadFile("/sys/firmware/devicetree/base/model")
	if err != nil || string(model) != "ARM Versatile PB\x00" ||
		os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 {
		return Observation{}, ErrInvalid
	}
	// Initialize Go's pipe poller before the steady-state descriptor census.
	a, b, err := os.Pipe()
	if err != nil {
		return Observation{}, err
	}
	if err := errors.Join(a.Close(), b.Close()); err != nil {
		return Observation{}, err
	}
	before, err := retainedFixtureFDCount()
	if err != nil {
		return Observation{}, err
	}
	caller, err := duplicateRoot(root)
	if err != nil {
		return Observation{}, err
	}
	code, err := plan.prepareRetainedCode(ctx, caller)
	callerErr := caller.Close()
	defer func() {
		if code != nil {
			if closeErr := code.release(); closeErr != nil {
				observation = Observation{}
				result = errors.Join(result, closeErr)
			}
		}
	}()
	if err != nil || callerErr != nil {
		return Observation{}, errors.Join(err, callerErr)
	}
	// Recheck original references after closing the duplicated caller input.
	if err := code.revalidate(ctx); err != nil {
		return Observation{}, err
	}
	got := code.observation
	if err := code.release(); err != nil {
		return Observation{}, err
	}
	if err := code.revalidate(ctx); !errors.Is(err, ErrUnavailable) {
		return Observation{}, errors.New("released NFS code remained usable")
	}
	code = nil
	after, err := retainedFixtureFDCount()
	if err != nil || after != before {
		return Observation{}, errors.Join(errors.New("NFS code descriptor census changed"), err)
	}
	if _, err := root.Stat(); err != nil {
		return Observation{}, err
	}
	return got, nil
}
