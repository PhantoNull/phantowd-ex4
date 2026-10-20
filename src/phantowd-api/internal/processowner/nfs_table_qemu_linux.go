//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"os"
	"runtime"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// NewNFSTableCaptureQEMU fixes one disposable ABI: original code/config/state
// O_PATH roots and the original read-only exportfs ELF. Its trusted containing
// input lifetime must remain locked and revalidated through capture/settlement.
// No caller-selectable arguments, privilege profile or generic FD injection.
func NewNFSTableCaptureQEMU(executable, input *os.File, objects [4]*os.File) (_ *CaptureOwner, result error) {
	if !nfsRuntimeFixtureGuardQEMU() {
		return nil, ErrInvalid
	}
	return newNFSTableCaptureQEMU(executable, input, objects)
}

func nfsRuntimeFixtureGuardQEMU() bool {
	if runtime.GOARCH != "arm" || os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 {
		return false
	}
	model, err := os.ReadFile("/sys/firmware/devicetree/base/model")
	if err != nil || string(model) != "ARM Versatile PB\x00" {
		return false
	}
	command, err := os.ReadFile("/proc/cmdline")
	if err != nil || len(command) > 4096 {
		return false
	}
	count := 0
	for _, word := range strings.Fields(string(command)) {
		if word == "phantowd_nfs_code_fixture=1" {
			count++
		}
	}
	return count == 1
}

func newNFSTableCaptureQEMU(executable, input *os.File, objects [4]*os.File) (_ *CaptureOwner, result error) {
	return newNFSCommandCaptureQEMU(executable, input, objects, "table-v1", nil, nil)
}

func newNFSCommandCaptureQEMU(executable, input *os.File, objects [4]*os.File, role string, extra []*os.File, valid func(*os.File, int) bool) (_ *CaptureOwner, result error) {
	c, err := NewCapture(CaptureSpec{
		ExecutableLabel: "/usr/sbin/phantowd-nfs-table-bootstrap", Args: []string{role},
		RunAs: &Credentials{UID: 0, GID: 0}, Timeout: 10 * time.Second, StopTimeout: time.Second,
	}, executable, input)
	if err != nil {
		return nil, err
	}
	defer func() {
		if result != nil {
			result = c.constructionRollback(result)
		}
	}()
	if c.inputStat.Size != 0 {
		return nil, ErrInvalid
	}
	var metadata [4]unix.Stat_t
	for index, source := range objects {
		if source == nil {
			return nil, ErrInvalid
		}
		raw, err := source.SyscallConn()
		if err != nil {
			return nil, ErrInvalid
		}
		fd := -1
		var dupErr error
		if err := raw.Control(func(value uintptr) { fd, dupErr = unix.FcntlInt(value, unix.F_DUPFD_CLOEXEC, 0) }); err != nil || dupErr != nil || fd < 0 {
			return nil, ErrInvalid
		}
		pin := os.NewFile(uintptr(fd), "fixed-nfs-table-input")
		c.fixtureInputs = append(c.fixtureInputs, pin)
		if unix.Fstat(fd, &metadata[index]) != nil || !nfsTableObjectQEMU(pin, index) {
			return nil, ErrInvalid
		}
	}
	digest, err := captureDigest(c.fixtureInputs[3], metadata[3], MaxCaptureExecutable)
	if err != nil {
		return nil, ErrInvalid
	}
	identities := make([]unix.Statx_t, len(extra))
	for index, source := range extra {
		pin, err := duplicateNFSKernelInputQEMU(source)
		if err != nil {
			return nil, err
		}
		c.fixtureInputs = append(c.fixtureInputs, pin)
		if valid == nil || !valid(pin, index) || nfsSourceStatQEMU(pin, &identities[index]) != nil {
			return nil, ErrInvalid
		}
	}
	c.fixtureInputsValid = func() bool {
		if len(c.fixtureInputs) != 4+len(extra) {
			return false
		}
		for index, pin := range c.fixtureInputs[:4] {
			var st unix.Stat_t
			original := metadata[index]
			if !nfsTableObjectQEMU(pin, index) || unix.Fstat(int(pin.Fd()), &st) != nil ||
				st.Dev != original.Dev || st.Ino != original.Ino || st.Mode != original.Mode || st.Uid != original.Uid || st.Gid != original.Gid {
				return false
			}
			if index == 3 {
				current, err := captureDigest(pin, st, MaxCaptureExecutable)
				if err != nil || !sameCaptureObject(st, original) || current != digest {
					return false
				}
			}
		}
		for index, pin := range c.fixtureInputs[4:] {
			var current unix.Statx_t
			if !valid(pin, index) || nfsSourceStatQEMU(pin, &current) != nil || !nfsSourceSameStatQEMU(current, identities[index]) {
				return false
			}
		}
		return true
	}
	if !c.fixtureInputsValid() {
		return nil, ErrInvalid
	}
	return c, nil
}

func nfsTableObjectQEMU(file *os.File, index int) bool {
	fd := int(file.Fd())
	flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
	var st unix.Stat_t
	var fs unix.Statfs_t
	if err != nil || unix.Fstat(fd, &st) != nil || unix.Fstatfs(fd, &fs) != nil || st.Uid != 0 || st.Gid != 0 || fs.Type != unix.TMPFS_MAGIC {
		return false
	}
	required := uint64(unix.ST_NOSUID | unix.ST_NODEV)
	if index != 2 {
		required |= unix.ST_RDONLY
	}
	if index == 1 || index == 2 {
		required |= unix.ST_NOEXEC
	}
	if uint64(fs.Flags)&required != required || (index == 2 && fs.Flags&unix.ST_RDONLY != 0) ||
		((index == 0 || index == 3) && fs.Flags&unix.ST_NOEXEC != 0) {
		return false
	}
	if index < 3 {
		mode := uint32(unix.S_IFDIR | 0755)
		if index == 2 {
			mode = unix.S_IFDIR | 0700
		}
		return flags&unix.O_PATH != 0 && flags&unix.O_DIRECTORY != 0 && st.Mode == mode
	}
	return flags&unix.O_PATH == 0 && flags&unix.O_ACCMODE == unix.O_RDONLY &&
		(st.Mode == unix.S_IFREG|0555 || st.Mode == unix.S_IFREG|0755) && st.Nlink == 1 && st.Size > 0 && st.Size <= MaxCaptureExecutable
}
