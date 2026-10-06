//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"errors"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// NewSambaStateObservationCaptureQEMU is one fixed disposable worker, not a
// generic extra-FD/action/secret API. It lists only synthetic qpwriter with empty
// regular stdin. The containing runtime Owner retains code/config/state
// authority and serializes this probe; no product constructor uses it.
func NewSambaStateObservationCaptureQEMU(executable, input *os.File, directories [7]*os.File) (_ *CaptureOwner, result error) {
	model, err := os.ReadFile("/sys/firmware/devicetree/base/model")
	if err != nil || string(model) != "ARM Versatile PB\x00" || os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 {
		return nil, ErrInvalid
	}
	c, err := NewCapture(CaptureSpec{
		ExecutableLabel: "/usr/sbin/phantowd-samba-root-launcher", Args: []string{"owned-state-observe"},
		RunAs: &Credentials{UID: 0, GID: 0}, Timeout: 10 * time.Second, StopTimeout: time.Second,
	}, executable, input)
	if err != nil {
		return nil, err
	}
	defer func() {
		if result != nil {
			result = errors.Join(result, c.release())
		}
	}()
	if c.inputStat.Size != 0 {
		return nil, ErrInvalid
	}
	var identities [7]unix.Stat_t
	for index, source := range directories {
		pin, err := duplicateSambaStateDirectoryQEMU(source)
		if err != nil {
			return nil, err
		}
		c.fixtureInputs = append(c.fixtureInputs, pin)
		if unix.Fstat(int(pin.Fd()), &identities[index]) != nil || identities[index].Dev != identities[0].Dev {
			return nil, ErrInvalid
		}
		for prior := 0; prior < index; prior++ {
			if identities[index].Ino == identities[prior].Ino {
				return nil, ErrInvalid
			}
		}
	}
	c.fixtureInputsValid = func() bool {
		for index, pin := range c.fixtureInputs {
			// Reuse descriptor/permission/attribute admission, not timestamps
			// or mutable TDB byte hashes. Each check's temporary FD is closed.
			checked, err := duplicateSambaStateDirectoryQEMU(pin)
			if err != nil {
				return false
			}
			var current unix.Stat_t
			statErr := unix.Fstat(int(checked.Fd()), &current)
			closeErr := checked.Close()
			if statErr != nil || closeErr != nil || current.Dev != identities[index].Dev || current.Ino != identities[index].Ino {
				return false
			}
		}
		return len(c.fixtureInputs) == 7
	}
	return c, nil
}
