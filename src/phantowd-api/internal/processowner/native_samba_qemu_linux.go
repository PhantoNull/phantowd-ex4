//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"os"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smbprovision"
	"golang.org/x/sys/unix"
)

// NativeSambaOperationQEMU selects fixed test-only verbs, never executables,
// arbitrary argv, paths or capabilities. No product constructor consumes it.
type NativeSambaOperationQEMU uint8

const (
	NativeSambaCheckQEMU NativeSambaOperationQEMU = iota + 1
	NativeSambaListQEMU
	NativeSambaCreateQEMU
	NativeSambaPasswordQEMU
	NativeSambaEnableQEMU
	NativeSambaDisableQEMU
	NativeSambaStatusQEMU
	NativeSambaRevokeQEMU
)

func (op NativeSambaOperationQEMU) valid(name string) bool {
	if op == NativeSambaCheckQEMU || op == NativeSambaListQEMU || op == NativeSambaStatusQEMU {
		return name == ""
	}
	return op >= NativeSambaCreateQEMU && op <= NativeSambaRevokeQEMU &&
		(name == "qpmanaged" || name == "qpsecond")
}

func (op NativeSambaOperationQEMU) argument() string {
	switch op {
	case NativeSambaCheckQEMU:
		return "check"
	case NativeSambaListQEMU:
		return "list"
	case NativeSambaCreateQEMU:
		return "create"
	case NativeSambaPasswordQEMU:
		return "password"
	case NativeSambaEnableQEMU:
		return "enable"
	case NativeSambaDisableQEMU:
		return "disable"
	case NativeSambaStatusQEMU:
		return "status"
	case NativeSambaRevokeQEMU:
		return "revoke"
	}
	return ""
}

// Fixed twelve-object ABI: config root/passwd/group/nsswitch/smb.conf, followed
// by state root/private/lock/state/cache/pid/rpc. Config is immutable; state
// directory identities survive legitimate mutable TDB contents. Input must be
// a sealed read-only memfd, empty except for the bounded repeated password.
func NewNativeSambaCaptureQEMU(executable, input *os.File, config [5]*os.File, state [7]*os.File, operation NativeSambaOperationQEMU, name string) (_ *CaptureOwner, result error) {
	model, err := os.ReadFile("/sys/firmware/devicetree/base/model")
	if err != nil || string(model) != "ARM Versatile PB\x00" || os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 || !operation.valid(name) {
		return nil, ErrInvalid
	}
	c, err := NewCapture(CaptureSpec{
		ExecutableLabel: "/usr/sbin/phantowd-samba-root-launcher",
		Args:            []string{"native-credential", operation.argument(), name},
		RunAs:           &Credentials{UID: 0, GID: 0}, Timeout: 10 * time.Second, StopTimeout: time.Second,
	}, executable, input)
	if err != nil {
		return nil, err
	}
	defer func() {
		if result != nil {
			result = errors.Join(result, c.release())
		}
	}()
	seals, err := unix.FcntlInt(c.input.Fd(), unix.F_GET_SEALS, 0)
	const required = unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	if err != nil || seals&required != required || c.inputStat.Size > int64(2*smbprovision.MaxPasswordBytes+2) {
		return nil, ErrInvalid
	}
	if operation == NativeSambaPasswordQEMU {
		data := make([]byte, c.inputStat.Size)
		defer clear(data)
		n, err := c.input.ReadAt(data, 0)
		lines := bytes.Split(data, []byte{'\n'})
		if err != nil || n != len(data) || len(lines) != 3 || len(lines[2]) != 0 ||
			!bytes.Equal(lines[0], lines[1]) || !smbprovision.ValidPassword(lines[0]) {
			return nil, ErrInvalid
		}
	} else if c.inputStat.Size != 0 {
		return nil, ErrInvalid
	}
	var metadata [12]unix.Stat_t
	var digests [5][sha256.Size]byte
	for index, source := range config {
		pin, err := duplicateNativeConfigurationModeQEMU(source, index == 0, index == 4)
		if err != nil {
			return nil, err
		}
		c.fixtureInputs = append(c.fixtureInputs, pin)
		if unix.Fstat(int(pin.Fd()), &metadata[index]) != nil || metadata[index].Dev != metadata[0].Dev {
			return nil, ErrInvalid
		}
		for prior := 0; prior < index; prior++ {
			if metadata[index].Ino == metadata[prior].Ino {
				return nil, ErrInvalid
			}
		}
		if index != 0 {
			digests[index], err = captureDigest(pin, metadata[index], 32768)
			if err != nil {
				return nil, ErrInvalid
			}
		}
	}
	for index, name := range []string{"passwd", "group", "nsswitch.conf", "samba/smb.conf"} {
		fd, err := unix.Openat2(int(c.fixtureInputs[0].Fd()), name, &unix.OpenHow{
			Flags:   unix.O_RDONLY | unix.O_CLOEXEC,
			Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV,
		})
		if err != nil {
			return nil, ErrInvalid
		}
		var actual unix.Stat_t
		statErr := unix.Fstat(fd, &actual)
		closeErr := unix.Close(fd)
		if statErr != nil || closeErr != nil || !sameCaptureObject(actual, metadata[index+1]) {
			return nil, ErrInvalid
		}
	}
	for index, source := range state {
		pin, err := duplicateSambaStateDirectoryQEMU(source)
		if err != nil {
			return nil, err
		}
		c.fixtureInputs = append(c.fixtureInputs, pin)
		if unix.Fstat(int(pin.Fd()), &metadata[index+5]) != nil || metadata[index+5].Dev != metadata[5].Dev {
			return nil, ErrInvalid
		}
		for prior := 0; prior < index; prior++ {
			if metadata[index+5].Ino == metadata[prior+5].Ino {
				return nil, ErrInvalid
			}
		}
	}
	c.fixtureInputsValid = func() bool {
		if len(c.fixtureInputs) != 12 {
			return false
		}
		for index, pin := range c.fixtureInputs {
			var checked *os.File
			var err error
			if index < 5 {
				checked, err = duplicateNativeConfigurationModeQEMU(pin, index == 0, index == 4)
			} else {
				checked, err = duplicateSambaStateDirectoryQEMU(pin)
			}
			if err != nil {
				return false
			}
			var current unix.Stat_t
			statErr := unix.Fstat(int(checked.Fd()), &current)
			closeErr := checked.Close()
			if statErr != nil || closeErr != nil || current.Dev != metadata[index].Dev || current.Ino != metadata[index].Ino {
				return false
			}
			if index < 5 {
				if !sameCaptureObject(current, metadata[index]) {
					return false
				}
				if index > 0 {
					digest, err := captureDigest(pin, current, 32768)
					if err != nil || digest != digests[index] {
						return false
					}
				}
			}
		}
		return true
	}
	if !c.fixtureInputsValid() {
		return nil, ErrInvalid
	}
	return c, nil
}
