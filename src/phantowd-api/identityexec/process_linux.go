// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package identityexec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func pinBinary(path string, owner uint32) (*os.File, unix.Stat_t, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, unix.Stat_t{}, ErrUnsafe
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return nil, unix.Stat_t{}, ErrUnsafe
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != owner ||
		st.Mode&03022 != 0 || st.Mode&0100 == 0 || st.Nlink != 1 || st.Size < 4 || st.Size > 64<<20 {
		return nil, unix.Stat_t{}, ErrUnsafe
	}
	// Buildroot's multicall BusyBox is root:root 4755. The executor opens and
	// dispatches only with real/effective UID 0, so this bit grants no privilege.
	// Never accept setgid/sticky or a setuid image owned by another identity.
	if st.Mode&04000 != 0 && (owner != 0 || st.Gid != 0 || os.Getuid() != 0 || os.Geteuid() != 0) {
		return nil, unix.Stat_t{}, ErrUnsafe
	}
	// Classify with O_PATH first: never open a FIFO/device for I/O. Execute the
	// retained regular object, not a replaceable path or an applet symlink.
	f, err := os.Open(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		return nil, unix.Stat_t{}, ErrUnsafe
	}
	header := make([]byte, 4)
	var after unix.Stat_t
	if _, err := f.ReadAt(header, 0); err != nil || !bytes.Equal(header, []byte{0x7f, 'E', 'L', 'F'}) ||
		unix.Fstat(int(f.Fd()), &after) != nil || !sameBinary(st, after) {
		f.Close()
		return nil, unix.Stat_t{}, ErrUnsafe
	}
	return f, st, nil
}

func sameBinary(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Size == b.Size && a.Mode == b.Mode &&
		a.Uid == b.Uid && a.Gid == b.Gid && a.Nlink == b.Nlink && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

// This is deliberately private. The public methods construct only the two
// fixed BusyBox vectors. The caller holds the executor lock and descriptor.
func runPinned(parent context.Context, binary *os.File, args []string, timeout time.Duration) error {
	if parent == nil || binary == nil || timeout <= 0 {
		return ErrInvalid
	}
	if err := parent.Err(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/proc/self/fd/3", args...)
	cmd.Args[0] = "busybox"
	cmd.ExtraFiles = []*os.File{binary}
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		err := unix.Kill(-cmd.Process.Pid, unix.SIGKILL)
		if errors.Is(err, unix.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.WaitDelay = time.Second
	// Never retain, log or return child diagnostics (which could contain private
	// identity data). Also bound drainage, rather than accumulating CombinedOutput.
	output := &boundedDiscard{}
	cmd.Stdout, cmd.Stderr = output, output
	if err := cmd.Run(); err != nil || ctx.Err() != nil || output.overflow {
		return ErrCommand
	}
	return nil
}

type boundedDiscard struct {
	count    int
	overflow bool
}

func (b *boundedDiscard) Write(p []byte) (int, error) {
	if len(p) > 16*1024-b.count {
		b.overflow = true
		return 0, ErrCommand
	}
	b.count += len(p)
	return len(p), nil
}
