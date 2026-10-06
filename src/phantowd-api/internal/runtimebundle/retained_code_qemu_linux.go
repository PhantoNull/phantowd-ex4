//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
)

// ProbeRetainedCodeQEMU is disposable qualification, not a product API, manifest
// authority or executable/storage grant. No retained descriptors are returned.
func (p *Plan) ProbeRetainedCodeQEMU(ctx context.Context, root *os.File) (observation Observation, result error) {
	if p == nil || len(p.files) == 0 || ctx == nil || root == nil {
		return Observation{}, ErrInvalid
	}
	model, err := os.ReadFile("/sys/firmware/devicetree/base/model")
	if err != nil || string(model) != "ARM Versatile PB\x00" ||
		os.Getuid() != 1801 || os.Geteuid() != 1801 || os.Getgid() != 1800 || os.Getegid() != 1800 {
		return Observation{}, ErrInvalid
	}
	before, err := retainedFixtureFDCount()
	if err != nil {
		return Observation{}, err
	}
	caller, err := duplicateRoot(root)
	if err != nil {
		return Observation{}, err
	}
	code, err := p.prepareRetainedCode(ctx, caller)
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
	// The existing point-in-time inspection has accepted these bytes already.
	// Qualify retention of a real dynamic daemon, not just a static helper.
	programPin := code.files["usr/sbin/smbd"]
	if programPin == nil {
		return Observation{}, ErrInvalid
	}
	program, err := elf.NewFile(programPin)
	if err != nil {
		return Observation{}, err
	}
	var interpreter, dynamic bool
	for _, segment := range program.Progs {
		interpreter = interpreter || segment.Type == elf.PT_INTERP
		dynamic = dynamic || segment.Type == elf.PT_DYNAMIC
	}
	if !interpreter || !dynamic {
		return Observation{}, errors.New("fixture daemon is not dynamic")
	}
	// The shared preparation primitive must not broaden the existing execution
	// adapter. The actual dynamic daemon remains forbidden there, including with
	// root credentials; only the future separate Samba Owner can qualify that.
	for _, credentials := range []processowner.Credentials{{UID: 1801, GID: 1800}, {UID: 0, GID: 0}} {
		callbackCalled := false
		owner, err := p.NewOwner(ctx, code.root, []processowner.MemberSpec{{Name: "must-refuse", Process: processowner.Spec{
			Executable: "/usr/sbin/smbd", RunAs: &credentials,
			Ready:        func(context.Context) (bool, error) { callbackCalled = true; return false, nil },
			ReadyTimeout: time.Second, ProbeInterval: 10 * time.Millisecond, StopTimeout: time.Second,
		}}})
		if owner != nil {
			return Observation{}, errors.Join(errors.New("generic adapter accepted Samba code"), owner.Close(context.Background()))
		}
		if !errors.Is(err, ErrInvalid) || callbackCalled {
			return Observation{}, errors.New("generic execution refusal changed")
		}
	}
	// Keep the trailing pathname/identity pass after all constructor inputs,
	// including this caller close; it must not be replaced by early census data.
	if err := code.revalidate(ctx); err != nil {
		return Observation{}, err
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := code.revalidate(canceled); !errors.Is(err, context.Canceled) {
		return Observation{}, errors.New("canceled revalidation was accepted")
	}
	if err := code.revalidate(ctx); err != nil {
		return Observation{}, err
	}
	got := code.observation
	if err := code.release(); err != nil {
		return Observation{}, err
	}
	if err := code.revalidate(ctx); !errors.Is(err, ErrUnavailable) {
		return Observation{}, errors.New("released code remained usable")
	}
	code = nil
	after, err := retainedFixtureFDCount()
	if err != nil || after != before {
		return Observation{}, errors.Join(fmt.Errorf("retained code descriptor count: before=%d after=%d", before, after), err)
	}
	return got, nil
}

func retainedFixtureFDCount() (int, error) {
	entries, err := os.ReadDir("/proc/self/fd")
	return len(entries), err
}
