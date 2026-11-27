// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smbprovision"
	"golang.org/x/sys/unix"
)

type sambaDirectory struct {
	device, inode, mount uint64
	flags, filesystem    int64
	mode, owner, group   uint32
}

func sambaDirectoryAt(directory *os.File) (sambaDirectory, error) {
	var st unix.Stat_t
	var fs unix.Statfs_t
	fd := int(directory.Fd())
	mount, err := descriptorMountID(fd)
	if err != nil || unix.Fstat(fd, &st) != nil || unix.Fstatfs(fd, &fs) != nil ||
		st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 || st.Gid != 0 {
		return sambaDirectory{}, ErrReviewRequired
	}
	return sambaDirectory{uint64(st.Dev), st.Ino, mount, int64(fs.Flags), int64(fs.Type),
		uint32(st.Mode), st.Uid, st.Gid}, nil
}

func (d *SambaDaemon) sambaProcessAlive() bool {
	if d.pidFD == nil || d.owner.current == nil || d.owner.current.exited() {
		return false
	}
	poll := []unix.PollFd{{Fd: int32(d.pidFD.Fd()), Events: unix.POLLIN}}
	result, err := unix.Poll(poll, 0)
	return err == nil && result == 0 && !d.owner.current.exited()
}

func viaProcDirectory(proc *os.File, name string, flags int) (*os.File, error) {
	// Only fixed /proc/<owned-pid> magic links are followed here.
	fd, err := unix.Openat(int(proc.Fd()), name, flags|unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.Join(ErrUnavailable, err)
	}
	return os.NewFile(uintptr(fd), "owned-samba-proc-"+name), nil
}

func sambaStatusObject(root *os.File, path string, directory bool) (*os.File, error) {
	flags := uint64(unix.O_PATH | unix.O_CLOEXEC)
	if directory {
		flags |= unix.O_DIRECTORY
	}
	fd, err := unix.Openat2(int(root.Fd()), path, &unix.OpenHow{Flags: flags,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS})
	if err != nil {
		return nil, errors.Join(ErrUnavailable, err)
	}
	return os.NewFile(uintptr(fd), "owned-samba-status-role"), nil
}

func (d *SambaDaemon) sambaStatusIdentity(proc, root *os.File) ([5]sambaDirectory, error) {
	var result [5]sambaDirectory
	if !d.sambaProcessAlive() {
		return result, ErrUnavailable
	}
	rootNow, err := viaProcDirectory(proc, "root", unix.O_DIRECTORY)
	if err != nil {
		return result, err
	}
	current, currentErr := sambaDirectoryAt(rootNow)
	held, heldErr := sambaDirectoryAt(root)
	const protected = unix.ST_NOSUID | unix.ST_NODEV
	if errors.Join(currentErr, heldErr, rootNow.Close()) != nil || current != held ||
		held.mode != unix.S_IFDIR|0755 || held.filesystem != unix.TMPFS_MAGIC ||
		held.flags&(protected|unix.ST_RDONLY) != protected|unix.ST_RDONLY {
		return result, ErrReviewRequired
	}
	result[0] = held

	for i, path := range []string{"etc", "state/private", "state/state", "state/lock"} {
		file, err := sambaStatusObject(root, path, true)
		if err != nil {
			return result, err
		}
		observed, err := sambaDirectoryAt(file)
		if err := errors.Join(err, file.Close()); err != nil {
			return result, err
		}
		if observed.flags&(protected|unix.ST_NOEXEC) != protected|unix.ST_NOEXEC {
			return result, ErrReviewRequired
		}
		if i < 3 {
			original, err := sambaDirectoryAt(d.files[i+1])
			if err != nil || observed.device != original.device || observed.inode != original.inode ||
				observed.filesystem != original.filesystem || observed.mode != original.mode ||
				observed.flags&unix.ST_RDONLY != original.flags&unix.ST_RDONLY {
				return result, ErrReviewRequired
			}
		} else if observed.filesystem != unix.TMPFS_MAGIC || observed.device != held.device ||
			observed.mode != unix.S_IFDIR|0700 || observed.flags&unix.ST_RDONLY != 0 {
			return result, ErrReviewRequired
		}
		result[i+1] = observed
	}
	exe, err := viaProcDirectory(proc, "exe", 0)
	if err != nil {
		return result, err
	}
	defer exe.Close()
	smbd, err := sambaStatusObject(root, "usr/sbin/smbd", false)
	if err != nil {
		return result, err
	}
	var actual, expected unix.Stat_t
	exeErr := unix.Fstat(int(exe.Fd()), &actual)
	smbdErr := unix.Fstat(int(smbd.Fd()), &expected)
	if errors.Join(exeErr, smbdErr, smbd.Close()) != nil ||
		actual.Mode&unix.S_IFMT != unix.S_IFREG || actual.Dev != expected.Dev || actual.Ino != expected.Ino ||
		!d.sambaProcessAlive() {
		return result, ErrReviewRequired
	}
	return result, nil
}

func (d *SambaDaemon) observeActivity(ctx context.Context) (smbprovision.Activity, error) {
	var empty smbprovision.Activity
	if ctx.Err() != nil || d.status != nil || !d.sambaProcessAlive() {
		return empty, errors.Join(ErrUnavailable, ctx.Err())
	}
	fd, err := unix.Open("/proc/"+strconv.Itoa(d.owner.current.pid),
		unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return empty, ErrUnavailable
	}
	proc := os.NewFile(uintptr(fd), "owned-samba-proc-directory")
	defer proc.Close()
	var fs unix.Statfs_t
	if unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.PROC_SUPER_MAGIC {
		return empty, ErrReviewRequired
	}
	root, err := viaProcDirectory(proc, "root", unix.O_DIRECTORY)
	if err != nil {
		return empty, err
	}
	defer root.Close()
	bound, err := d.sambaStatusIdentity(proc, root)
	if err != nil {
		if errors.Is(err, ErrReviewRequired) {
			d.review = true
		}
		return empty, fmt.Errorf("verify owned Samba status root: %w", err)
	}
	input, err := smbprovision.SealWorkerInput(nil)
	if err != nil {
		return empty, err
	}
	defer input.Close()
	capture, err := NewCapture(CaptureSpec{
		ExecutableLabel: "/usr/bin/phantowd-api", Args: []string{"--run-rc0-samba-status"},
		RunAs: &Credentials{}, Timeout: 15 * time.Second, StopTimeout: time.Second,
	}, d.files[len(d.files)-1], input)
	if err != nil {
		return empty, err
	}
	retained, err := unix.FcntlInt(root.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return empty, errors.Join(err, capture.Close(context.Background()))
	}
	capture.fixtureInputs = []*os.File{os.NewFile(uintptr(retained), "owned-samba-status-root")}
	capture.fixtureInputsValid = func() bool {
		current, err := d.sambaStatusIdentity(proc, capture.fixtureInputs[0])
		return err == nil && current == bound
	}
	capture.stdoutLimit = smbprovision.MaxStatusBytes
	capture.dieWithParent = true
	d.status = capture
	output, captureErr := capture.Capture(ctx)
	defer clear(output.Stdout)
	defer clear(output.Stderr)
	if err := capture.Close(context.Background()); err != nil {
		d.review = true
		return empty, ErrReviewRequired
	}
	d.status = nil
	if errors.Is(captureErr, ErrReviewRequired) {
		d.review = true
		return empty, ErrReviewRequired
	}
	if captureErr != nil {
		return empty, fmt.Errorf("capture owned Samba status: %w", captureErr)
	}
	// Samba probes the interfaces named in the service configuration. The
	// disconnected status namespace intentionally has none of those links.
	const isolatedNetworkNotice = "WARNING: no network interfaces found\n"
	expectedDiagnostics := len(output.Stderr) == 0 || string(output.Stderr) == isolatedNetworkNotice
	if output.Kind != CaptureExited || output.ExitCode != 0 || !expectedDiagnostics {
		return empty, fmt.Errorf("Samba status worker outcome %d, exit %d, diagnostics %d bytes: %w",
			output.Kind, output.ExitCode, len(output.Stderr), ErrUnavailable)
	}
	if !d.sambaProcessAlive() {
		return empty, ErrUnavailable
	}
	result, err := smbprovision.ParseActivity(output.Stdout)
	if err != nil {
		return empty, fmt.Errorf("Samba status output does not match the admitted census: %w", ErrUnavailable)
	}
	return result, nil
}
