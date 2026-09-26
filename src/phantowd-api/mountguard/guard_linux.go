// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package mountguard pins a previously qualified Linux mount and resolves
// directory descriptors beneath it. It is not a volume identity resolver,
// permission checker, service activator or mount/unmount implementation.
package mountguard

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

var (
	ErrUnsafe      = errors.New("unsafe mount or relative directory path")
	ErrMismatch    = errors.New("qualified mount identity or state changed")
	ErrUnsupported = errors.New("required Linux mount protection unavailable")
	ErrUnavailable = errors.New("mount or directory unavailable")
	ErrClosed      = errors.New("mount guard is closed")
)

// Expected must come from a trusted volume-qualification/lifecycle component,
// never directly from HTTP or a scan of whatever happens to occupy a path.
// MountID is STATX_MNT_ID_UNIQUE, NOT the recyclable /proc mountinfo ID.
// FilesystemType is the statfs magic, not evidence of filesystem integrity.
// The observation is valid only in the same running kernel/mount namespace;
// do not persist it as a disk identity or reuse it after reboot.
type Expected struct {
	MountID         uint64
	RootInode       uint64
	DeviceMajor     uint32
	DeviceMinor     uint32
	FilesystemType  uint32
	RequireWritable bool
}

// Root must not be copied. Close/Verify/OpenDirectory are serialized. Returned
// directory descriptors have their own lifetime and must be closed by callers.
type Root struct {
	mu       sync.Mutex
	fd       int
	path     string
	expected Expected
	closed   bool
	ready    bool
}

// Open retains an O_PATH directory descriptor after checking the complete
// expected tuple and mount-root attribute. It creates nothing, follows no
// symlinks and never substitutes an older/weaker syscall when unsupported.
func Open(path string, expected Expected) (*Root, error) {
	if !validAbsolute(path) || expected.MountID == 0 || expected.RootInode == 0 || expected.FilesystemType == 0 {
		return nil, ErrUnsafe
	}
	fd, err := openPath(unix.AT_FDCWD, path, false)
	if err != nil {
		return nil, err
	}
	if err := matchFD(fd, expected, true); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return &Root{fd: fd, path: path, expected: expected, ready: true}, nil
}

// Verify checks that the named anchor still resolves to this qualified mount.
// This is a point-in-time check, not a revocation mechanism for descriptors
// already handed to callers or an authorization to launch path-based daemons.
func (r *Root) Verify() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.verify()
}

func (r *Root) verify() error {
	if r.closed || !r.ready {
		return ErrClosed
	}
	fd, err := openPath(unix.AT_FDCWD, r.path, false)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := matchFD(fd, r.expected, true); err != nil {
		return err
	}
	return matchFD(r.fd, r.expected, true)
}

// OpenDirectory resolves only existing directories on the retained mount.
// BENEATH + NO_SYMLINKS + NO_MAGICLINKS + NO_XDEV prevent escaping, including
// through bind mounts. The returned O_PATH descriptor cannot read/write file
// contents; callers must not replace it with an unchecked textual path.
// It does not prove that the caller's eventual SMB/NFS identity has access.
func (r *Root) OpenDirectory(relative string) (*os.File, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || !r.ready {
		return nil, ErrClosed
	}
	if !validRelative(relative) {
		return nil, ErrUnsafe
	}
	if err := r.verify(); err != nil {
		return nil, err
	}
	fd, err := openPath(r.fd, relative, true)
	if err != nil {
		return nil, err
	}
	if err := matchFD(fd, r.expected, false); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return os.NewFile(uintptr(fd), "qualified-directory"), nil
}

func (r *Root) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || !r.ready {
		return nil
	}
	r.closed = true
	if unix.Close(r.fd) != nil {
		return ErrUnavailable
	}
	return nil
}

func validAbsolute(path string) bool {
	return len(path) <= 4096 && path != "/" && filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.ContainsRune(path, 0)
}
func validRelative(path string) bool {
	return len(path) <= 1024 && fs.ValidPath(path) && !strings.ContainsAny(path, "\\\x00")
}

func openPath(parent int, path string, beneath bool) (int, error) {
	resolve := uint64(unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS)
	if beneath {
		resolve |= unix.RESOLVE_BENEATH | unix.RESOLVE_NO_XDEV
	}
	fd, err := unix.Openat2(parent, path, &unix.OpenHow{Flags: unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: resolve})
	if err != nil {
		return -1, classify(err)
	}
	return fd, nil
}

func classify(err error) error {
	if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EOPNOTSUPP) {
		return ErrUnsupported
	}
	if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.EXDEV) {
		return ErrUnsafe
	}
	return ErrUnavailable
}

func matchFD(fd int, expected Expected, root bool) error {
	var st unix.Statx_t
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_NO_AUTOMOUNT, unix.STATX_BASIC_STATS|unix.STATX_MNT_ID_UNIQUE, &st); err != nil {
		return classify(err)
	}
	var filesystem unix.Statfs_t
	if err := unix.Fstatfs(fd, &filesystem); err != nil {
		return classify(err)
	}
	return match(st, filesystem, expected, root)
}

func match(st unix.Statx_t, filesystem unix.Statfs_t, expected Expected, root bool) error {
	const required = unix.STATX_TYPE | unix.STATX_INO | unix.STATX_MNT_ID_UNIQUE
	if st.Mask&required != required || (root && st.Attributes_mask&unix.STATX_ATTR_MOUNT_ROOT == 0) {
		return ErrUnsupported
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mnt_id != expected.MountID || st.Dev_major != expected.DeviceMajor || st.Dev_minor != expected.DeviceMinor || uint32(filesystem.Type) != expected.FilesystemType || (expected.RequireWritable && filesystem.Flags&unix.ST_RDONLY != 0) {
		return ErrMismatch
	}
	if root && (st.Attributes&unix.STATX_ATTR_MOUNT_ROOT == 0 || st.Ino != expected.RootInode) {
		return ErrMismatch
	}
	return nil
}
