//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path"
	"runtime"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

// ErrStageIncomplete means staging may have changed its disposable destination.
// Discard the entire test-owned tree. Do not publish, resume or retry it.
var ErrStageIncomplete = errors.New("disposable runtime staging incomplete")

// StageQEMU is a test-only construction prototype, excluded from product builds.
// The caller exclusively owns an empty root:root 0700 tmpfs directory, and must
// discard it on any failure after mutation. Source is a pinned local read-only
// filesystem, not a storage grant. Copies never overwrite or preserve xattrs,
// hardlinks, ownership or source permissions. Expected hashes are checked while
// copying. Success is not approval: the caller must seal and Inspect separately.
// Neither this prototype nor its fixture manifest is authenticated authority.
func (p *Plan) StageQEMU(ctx context.Context, source, destination *os.File) (result error) {
	if p == nil || len(p.files) == 0 || ctx == nil || source == nil || destination == nil || os.Geteuid() != 0 {
		return ErrInvalid
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	defer runtime.KeepAlive(source)
	defer runtime.KeepAlive(destination)
	src, err := stagePin(source)
	if err != nil {
		return err
	}
	defer unix.Close(src)
	dst, err := stagePin(destination)
	if err != nil {
		return err
	}
	defer unix.Close(dst)
	sourceRoot, err := inspectMetadata(src, unix.S_IFDIR, 0)
	if err != nil {
		return err
	}
	destinationRoot, err := stageDestinationMetadata(dst, unix.S_IFDIR, 0)
	if err != nil || destinationRoot.Mode&07777 != 0700 {
		return ErrMismatch
	}
	root, err := openBeneath(dst, ".", unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return err
	}
	dir := os.NewFile(uintptr(root), "disposable-stage-directory")
	defer dir.Close()
	if err := stageNoACL(root); err != nil {
		return err
	}
	entries, err := dir.ReadDir(1)
	if !errors.Is(err, io.EOF) || len(entries) != 0 {
		return ErrMismatch
	}
	// This flag is set BEFORE each potentially mutating syscall, including a
	// failed syscall whose outcome must never be treated as a clean reusable tree.
	mutating := false
	defer func() {
		if result != nil && mutating {
			result = errors.Join(ErrStageIncomplete, result)
		}
	}()
	var directories []string
	for name, kind := range p.nodes {
		if name != "." && kind == 'd' {
			directories = append(directories, name)
		}
	}
	slices.SortFunc(directories, func(a, b string) int {
		if depth := strings.Count(a, "/") - strings.Count(b, "/"); depth != 0 {
			return depth
		}
		return strings.Compare(a, b)
	})
	for _, name := range directories {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		parent, err := openBeneath(dst, path.Dir(name), unix.O_PATH|unix.O_DIRECTORY)
		if err != nil {
			return err
		}
		mutating = true
		err = unix.Mkdirat(parent, path.Base(name), 0700)
		_ = unix.Close(parent)
		if err != nil {
			return ErrMismatch
		}
	}
	for _, file := range p.files {
		mutating = true
		if err := stageFile(ctx, src, dst, sourceRoot.Mnt_id, destinationRoot.Mnt_id, file); err != nil {
			return err
		}
	}
	for _, alias := range p.aliases {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		parent, err := openBeneath(dst, path.Dir(alias.Path), unix.O_PATH|unix.O_DIRECTORY)
		if err != nil {
			return err
		}
		mutating = true
		err = unix.Symlinkat("/"+alias.Target, parent, path.Base(alias.Path))
		_ = unix.Close(parent)
		if err != nil {
			return ErrMismatch
		}
	}
	// Publish traversal permissions last, deepest-first. This does not seal the
	// filesystem or grant execution; only the fixed root caller can mutate it.
	slices.Reverse(directories)
	for _, name := range append(directories, ".") {
		fd, err := openBeneath(dst, name, unix.O_RDONLY|unix.O_DIRECTORY)
		if err != nil {
			return err
		}
		_, err = stageDestinationMetadata(fd, unix.S_IFDIR, destinationRoot.Mnt_id)
		if err == nil {
			err = stageNoACL(fd)
		}
		if err == nil {
			mutating = true
			err = unix.Fchmod(fd, 0755)
		}
		_ = unix.Close(fd)
		if err != nil {
			return ErrMismatch
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	finalSource, err := inspectMetadata(src, unix.S_IFDIR, sourceRoot.Mnt_id)
	if err != nil || finalSource != sourceRoot {
		return ErrMismatch
	}
	return nil
}

func stagePin(file *os.File) (int, error) {
	fd, err := unix.FcntlInt(file.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return -1, ErrUnavailable
	}
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_PATH == 0 || flags&unix.O_DIRECTORY == 0 {
		_ = unix.Close(fd)
		return -1, ErrInvalid
	}
	return fd, nil
}

func stageDestinationMetadata(fd int, kind uint16, mount uint64) (unix.Statx_t, error) {
	var st unix.Statx_t
	var fs unix.Statfs_t
	const required = unix.STATX_BASIC_STATS | unix.STATX_MNT_ID_UNIQUE
	if unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_NO_AUTOMOUNT, required, &st) != nil ||
		st.Mask&required != required || st.Mnt_id == 0 || unix.Fstatfs(fd, &fs) != nil {
		return st, ErrUnavailable
	}
	if fs.Type != unix.TMPFS_MAGIC || fs.Flags&unix.ST_RDONLY != 0 || st.Mode&unix.S_IFMT != kind ||
		st.Uid != 0 || st.Gid != 0 || st.Mode&0022 != 0 || st.Mode&07000 != 0 ||
		(mount != 0 && st.Mnt_id != mount) {
		return st, ErrMismatch
	}
	return st, nil
}

func stageNoACL(fd int) error {
	for _, name := range []string{"system.posix_acl_access", "system.posix_acl_default", "security.capability"} {
		if _, err := unix.Fgetxattr(fd, name, nil); !errors.Is(err, unix.ENODATA) && !errors.Is(err, unix.ENOTSUP) {
			return ErrMismatch
		}
	}
	return nil
}

func stageFile(ctx context.Context, source, destination int, sourceMount, destinationMount uint64, expected File) error {
	src, err := openBeneath(source, expected.Path, unix.O_RDONLY)
	if err != nil {
		return err
	}
	in := os.NewFile(uintptr(src), "disposable-stage-source")
	defer in.Close()
	before, err := inspectMetadata(src, unix.S_IFREG, sourceMount)
	if err != nil || before.Size != uint64(expected.Size) || before.Nlink != 1 {
		return ErrMismatch
	}
	if err := stageNoACL(src); err != nil {
		return err
	}
	dst, err := unix.Openat2(destination, expected.Path, &unix.OpenHow{
		Flags: unix.O_WRONLY | unix.O_CREAT | unix.O_EXCL | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK,
		Mode:  0600, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV,
	})
	if err != nil {
		return ErrMismatch
	}
	out := os.NewFile(uintptr(dst), "disposable-stage-copy")
	defer out.Close()
	created, err := stageDestinationMetadata(dst, unix.S_IFREG, destinationMount)
	if err != nil || created.Nlink != 1 || stageNoACL(dst) != nil {
		return ErrMismatch
	}
	hash := sha256.New()
	buffer := make([]byte, 32<<10)
	reader := io.LimitReader(in, expected.Size+1)
	var total int64
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		count, readErr := reader.Read(buffer)
		if count > 0 {
			if total+int64(count) > expected.Size {
				return ErrMismatch
			}
			if written, err := out.Write(buffer[:count]); err != nil || written != count {
				return ErrUnavailable
			}
			_, _ = hash.Write(buffer[:count])
			total += int64(count)
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return ErrUnavailable
		}
	}
	var digest [32]byte
	copy(digest[:], hash.Sum(nil))
	after, err := inspectMetadata(src, unix.S_IFREG, sourceMount)
	if err != nil || after != before || total != expected.Size || digest != expected.SHA256 ||
		unix.Fchmod(dst, expected.Mode) != nil {
		return ErrMismatch
	}
	final, err := stageDestinationMetadata(dst, unix.S_IFREG, destinationMount)
	if err != nil || final.Size != uint64(expected.Size) || final.Mode&07777 != uint16(expected.Mode) ||
		final.Nlink != 1 || stageNoACL(dst) != nil {
		return ErrMismatch
	}
	return out.Close()
}
