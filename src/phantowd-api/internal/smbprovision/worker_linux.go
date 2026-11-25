// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package smbprovision

import (
	"bytes"
	"errors"
	"os"
	"strconv"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
	"golang.org/x/sys/unix"
)

const (
	WorkerCheck    = "check"
	WorkerObserve  = "observe"
	WorkerCreate   = "create-disabled"
	WorkerPassword = "set-password-disabled"
	WorkerEnable   = "enable"
)

// SealWorkerInput creates the read-only, offset-zero stdin description.
func SealWorkerInput(data []byte) (reader *os.File, result error) {
	if len(data) > 2*MaxPasswordBytes+2 || os.Getuid() != 0 || os.Geteuid() != 0 {
		return nil, ErrInvalid
	}
	fd, err := unix.MemfdCreate("samba-enrollment-input", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, err
	}
	writer := os.NewFile(uintptr(fd), "samba-enrollment-input")
	defer func() {
		if err := writer.Close(); err != nil {
			result = errors.Join(result, err)
			if reader != nil {
				result = errors.Join(result, reader.Close())
				reader = nil
			}
		}
	}()
	if err := errors.Join(writer.Chown(0, 0), writer.Chmod(0600)); err != nil {
		return nil, err
	}
	if _, err := writer.Write(data); err != nil {
		return nil, err
	}
	const required = unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	if _, err := unix.FcntlInt(writer.Fd(), unix.F_ADD_SEALS, required); err != nil {
		return nil, err
	}
	readerFD, err := unix.Open("/proc/self/fd/"+strconv.Itoa(fd), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(readerFD), "sealed-samba-enrollment-input"), nil
}

// WorkerCommand maps a typed enrollment operation to the installed program and
// arguments inside the isolated root. Names use the native registry grammar.
func WorkerCommand(operation, name string) (string, []string, error) {
	const config = "/etc/samba/smb.conf"
	switch operation {
	case WorkerCheck, WorkerObserve:
		if name != "" {
			return "", nil, ErrInvalid
		}
		if operation == WorkerCheck {
			return "/usr/bin/testparm", []string{"testparm", "-s", config}, nil
		}
		return "/usr/bin/pdbedit", []string{"pdbedit", "-L", "-v", "-s", config}, nil
	case WorkerCreate, WorkerPassword, WorkerEnable:
		registry, err := serviceaccounts.New(1000, 1000)
		if err != nil {
			return "", nil, ErrInvalid
		}
		registry.Accounts = []serviceaccounts.Account{{ID: "worker", Name: name, UID: 1000, GID: 1000, State: serviceaccounts.Disabled}}
		if registry.Validate() != nil {
			return "", nil, ErrInvalid
		}
		var options []string
		switch operation {
		case WorkerCreate:
			options = []string{"-a", "-d"}
		case WorkerPassword:
			options = []string{"-s", "--set-password-disabled"}
		case WorkerEnable:
			options = []string{"-e"}
		}
		return "/usr/bin/smbpasswd", append(append([]string{"smbpasswd"}, options...), "-c", config, name), nil
	default:
		return "", nil, ErrInvalid
	}
}

// VerifyWorkerInput admits only an original read-only sealed memory file at
// offset zero. Password input is two identical bounded lines. The verifier
// leaves the descriptor offset intact for the native program.
func VerifyWorkerInput(file *os.File, operation string) error {
	if file == nil {
		return ErrInvalid
	}
	fd := int(file.Fd())
	flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
	seals, sealErr := unix.FcntlInt(file.Fd(), unix.F_GET_SEALS, 0)
	const required = unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	var stat unix.Stat_t
	var fs unix.Statfs_t
	if err != nil || flags&(unix.O_ACCMODE|unix.O_PATH) != unix.O_RDONLY || sealErr != nil || seals&required != required ||
		unix.Fstat(fd, &stat) != nil || stat.Mode != unix.S_IFREG|0600 || stat.Uid != 0 || stat.Gid != 0 ||
		stat.Size < 0 || stat.Size > 2*MaxPasswordBytes+2 || unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.TMPFS_MAGIC {
		return ErrInvalid
	}
	if offset, err := unix.Seek(fd, 0, 1); err != nil || offset != 0 {
		return ErrInvalid
	}
	if operation != WorkerPassword {
		if stat.Size != 0 {
			return ErrInvalid
		}
		return nil
	}
	data := make([]byte, stat.Size)
	defer clear(data)
	if _, err := file.ReadAt(data, 0); err != nil {
		return ErrInvalid
	}
	lines := bytes.Split(data, []byte{'\n'})
	if len(lines) != 3 || len(lines[2]) != 0 || !bytes.Equal(lines[0], lines[1]) || !ValidPassword(lines[0]) {
		return ErrInvalid
	}
	return nil
}
