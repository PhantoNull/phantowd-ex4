// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package unixidentity

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

var (
	ErrUnsafe  = errors.New("unsafe local identity source")
	ErrChanged = errors.New("local identity source changed during observation")
	ErrRead    = errors.New("local identity source unavailable")
	ErrNSS     = errors.New("unsupported identity name-service configuration")
)

type pinnedIdentityFile struct {
	name   string
	pin    int
	file   *os.File
	before unix.Stat_t
}

// ReadLocal pins exactly passwd, group and nsswitch.conf in an explicitly
// supplied trusted directory. No symlinks, special files, hardlinks, writable
// group/other sources or unexpected owners are accepted. Missing openat2 is a
// refusal, never a weaker fallback. It reads no shadow/passdb or user data.
//
// Metadata/path rechecks bound one observation window, not a cross-file atomic
// transaction or an authorization lease. The caller must own trusted parents
// and serialize all writers separately before using a result to plan mutations.
// Kernel I/O may block; a future privileged caller must supervise execution.
func ReadLocal(directory string, ownerUID uint32) (Snapshot, error) {
	return readLocal(directory, ownerUID, nil)
}

// afterRead is an internal deterministic race-test seam, never a caller option.
func readLocal(directory string, ownerUID uint32, afterRead func()) (Snapshot, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return Snapshot{}, ErrUnsafe
	}
	root, err := unix.Openat2(unix.AT_FDCWD, directory, &unix.OpenHow{Flags: unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return Snapshot{}, ErrUnsafe
	}
	defer unix.Close(root)
	var rootBefore unix.Stat_t
	if unix.Fstat(root, &rootBefore) != nil || !trustedIdentityObject(rootBefore, ownerUID, true) {
		return Snapshot{}, ErrUnsafe
	}
	files := []pinnedIdentityFile{}
	defer func() {
		for _, p := range files {
			if p.file != nil {
				p.file.Close()
			}
			unix.Close(p.pin)
		}
	}()
	for _, name := range []string{"passwd", "group", "nsswitch.conf"} {
		// O_PATH can classify a FIFO/device without opening it for actual I/O.
		pin, err := unix.Openat2(root, name, &unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV})
		if err != nil {
			return Snapshot{}, ErrUnsafe
		}
		files = append(files, pinnedIdentityFile{name: name, pin: pin})
		p := &files[len(files)-1]
		if unix.Fstat(pin, &p.before) != nil || !trustedIdentityObject(p.before, ownerUID, false) {
			return Snapshot{}, ErrUnsafe
		}
		limit := int64(MaxFileBytes)
		if name == "nsswitch.conf" {
			limit = MaxNSSBytes
		}
		if p.before.Size <= 0 || p.before.Size > limit {
			return Snapshot{}, ErrUnsafe
		}
	}
	// All three metadata baselines are recorded before reading any content.
	for i := range files {
		p := &files[i]
		// Reopen this verified regular object, not its mutable directory name.
		f, err := os.Open(fmt.Sprintf("/proc/self/fd/%d", p.pin))
		if err != nil {
			return Snapshot{}, ErrRead
		}
		p.file = f
		var current unix.Stat_t
		if unix.Fstat(int(f.Fd()), &current) != nil || !sameIdentityObject(p.before, current) {
			return Snapshot{}, ErrChanged
		}
	}
	nss, err := io.ReadAll(io.LimitReader(files[2].file, MaxNSSBytes+1))
	if err != nil {
		return Snapshot{}, ErrRead
	}
	if !FilesOnlyNSS(nss) {
		return Snapshot{}, ErrNSS
	}
	snapshot, err := Parse(files[0].file, files[1].file)
	if err != nil {
		return Snapshot{}, ErrInvalid
	}
	if afterRead != nil {
		afterRead()
	}
	for _, p := range files {
		var current, named unix.Stat_t
		if unix.Fstat(p.pin, &current) != nil || unix.Fstatat(root, p.name, &named, unix.AT_SYMLINK_NOFOLLOW) != nil ||
			!sameIdentityObject(p.before, current) || !sameIdentityObject(p.before, named) {
			return Snapshot{}, ErrChanged
		}
	}
	var rootAfter, rootNamed unix.Stat_t
	if unix.Fstat(root, &rootAfter) != nil || !sameIdentityObject(rootBefore, rootAfter) {
		return Snapshot{}, ErrChanged
	}
	reopened, err := unix.Openat2(unix.AT_FDCWD, directory, &unix.OpenHow{Flags: unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return Snapshot{}, ErrChanged
	}
	defer unix.Close(reopened)
	if unix.Fstat(reopened, &rootNamed) != nil || !sameIdentityObject(rootBefore, rootNamed) {
		return Snapshot{}, ErrChanged
	}
	return snapshot, nil
}

func trustedIdentityObject(st unix.Stat_t, owner uint32, directory bool) bool {
	want := uint32(unix.S_IFREG)
	if directory {
		want = unix.S_IFDIR
	}
	return st.Mode&unix.S_IFMT == want && st.Uid == owner && st.Mode&07022 == 0 && (directory || st.Nlink == 1)
}

func sameIdentityObject(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid && a.Nlink == b.Nlink && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}
