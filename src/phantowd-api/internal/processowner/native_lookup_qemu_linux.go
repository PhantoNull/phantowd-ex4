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

// NewNativeLookupCaptureQEMU fixes one read-only fixture ABI: config directory,
// passwd, group, nsswitch.conf, in that order. The trusted configuration owner
// supplies already-qualified objects and expected contents; this layer grants
// no identity authority. No paths, account/action selectors or secrets enter.
// Generic CaptureSpec still has no descriptor-injection or root-profile option.
func NewNativeLookupCaptureQEMU(executable, input *os.File, configuration [4]*os.File) (_ *CaptureOwner, result error) {
	model, err := os.ReadFile("/sys/firmware/devicetree/base/model")
	if err != nil || string(model) != "ARM Versatile PB\x00" || os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 {
		return nil, ErrInvalid
	}
	c, err := NewCapture(CaptureSpec{
		ExecutableLabel: "/usr/sbin/phantowd-samba-root-launcher", Args: []string{"native-lookup-retained"},
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
	var metadata [4]unix.Stat_t
	var digests [4][32]byte
	for index, source := range configuration {
		pin, err := duplicateNativeConfigurationQEMU(source, index == 0)
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
		if index > 0 {
			digests[index], err = captureDigest(pin, metadata[index], 32768)
			if err != nil {
				return nil, ErrInvalid
			}
		}
	}
	// Confirm role/parent correspondence using the original directory, not a
	// host pathname. Cross-mount, symlink, swapped or unrelated files refuse.
	for index, name := range []string{"passwd", "group", "nsswitch.conf"} {
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
	c.fixtureInputsValid = func() bool {
		if len(c.fixtureInputs) != 4 {
			return false
		}
		for index, pin := range c.fixtureInputs {
			checked, err := duplicateNativeConfigurationQEMU(pin, index == 0)
			if err != nil {
				return false
			}
			var current unix.Stat_t
			statErr := unix.Fstat(int(checked.Fd()), &current)
			closeErr := checked.Close()
			if statErr != nil || closeErr != nil || !sameCaptureObject(current, metadata[index]) {
				return false
			}
			if index > 0 {
				digest, err := captureDigest(pin, current, 32768)
				if err != nil || digest != digests[index] {
					return false
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

func duplicateNativeConfigurationQEMU(source *os.File, directory bool) (*os.File, error) {
	return duplicateNativeConfigurationModeQEMU(source, directory, false)
}

func duplicateNativeConfigurationModeQEMU(source *os.File, directory, private bool) (*os.File, error) {
	if source == nil {
		return nil, ErrInvalid
	}
	raw, err := source.SyscallConn()
	if err != nil {
		return nil, ErrInvalid
	}
	fd := -1
	var duplicateErr error
	if err := raw.Control(func(value uintptr) { fd, duplicateErr = unix.FcntlInt(value, unix.F_DUPFD_CLOEXEC, 0) }); err != nil || duplicateErr != nil || fd < 0 {
		return nil, ErrInvalid
	}
	pin := os.NewFile(uintptr(fd), "fixed-native-config-input")
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	var st unix.Stat_t
	var fs unix.Statfs_t
	mode := uint32(unix.S_IFREG | 0644)
	if private {
		mode = unix.S_IFREG | 0600
	}
	if directory {
		mode = unix.S_IFDIR | 0755
	}
	const required = unix.ST_RDONLY | unix.ST_NOSUID | unix.ST_NODEV | unix.ST_NOEXEC
	if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY || flags&unix.O_PATH != 0 ||
		(flags&unix.O_DIRECTORY != 0) != directory || unix.Fstat(fd, &st) != nil ||
		st.Mode != mode || st.Uid != 0 || st.Gid != 0 ||
		(!directory && (st.Nlink != 1 || st.Size <= 0 || st.Size > 32768)) ||
		unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.TMPFS_MAGIC || fs.Flags&required != required {
		_ = pin.Close()
		return nil, ErrInvalid
	}
	for _, attribute := range []string{"system.posix_acl_access", "system.posix_acl_default", "security.capability"} {
		if _, err := unix.Fgetxattr(fd, attribute, nil); !errors.Is(err, unix.ENODATA) && !errors.Is(err, unix.ENOTSUP) {
			_ = pin.Close()
			return nil, ErrInvalid
		}
	}
	return pin, nil
}
