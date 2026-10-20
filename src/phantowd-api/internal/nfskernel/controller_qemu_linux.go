//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package nfskernel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

func SocketRequestQEMU(fd int) ([]byte, error) {
	if fd < 0 || uint64(fd) > 2147483647 {
		return nil, ErrRefused
	}
	return []byte(strconv.Itoa(fd) + "\n"), nil
}

// One fixed disposable-guest kernel component, NOT a complete NFS backend or
// exclusive product control domain. The surrounding fixture owns its mounts,
// policy, export/mountd/rpcbind processes and consumers separately.
type ControllerQEMU struct {
	original                         *ControllerQEMU
	gate                             chan struct{}
	directory, network, mounts       *os.File
	root                             unix.Statx_t
	ns                               [2]unix.Stat_t
	socket                           int
	socketIdentity                   nfsSocketIdentityQEMU
	unattached                       *unattachedSocketQEMU
	started, stopped, closed, review bool
	uncertain                        *os.File
	phase                            string // Fixed fixture label only; no paths or source data.
}

var kernelRetention struct {
	sync.Mutex
	objects []*ControllerQEMU
	active  *ControllerQEMU
}

func (k *ControllerQEMU) retain() error {
	if !k.review {
		k.review = true
		kernelRetention.Lock()
		kernelRetention.objects = append(kernelRetention.objects, k)
		kernelRetention.Unlock()
	}
	return fmt.Errorf("NFS fixture kernel phase=%s: %w", k.phase, ErrRefused)
}

func openQEMU(ctx context.Context, reboot bool) (*ControllerQEMU, error) {
	if ctx == nil || ctx.Err() != nil || !fixtureGuardQEMU(reboot) {
		return nil, ErrRefused
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	k := &ControllerQEMU{gate: make(chan struct{}, 1), socket: -1, phase: "open"}
	k.original = k
	fail := func() (*ControllerQEMU, error) { return nil, k.retain() }
	// After a failed construction/transaction no new controller can erase review.
	kernelRetention.Lock()
	retained := len(kernelRetention.objects) != 0 || kernelRetention.active != nil
	if !retained {
		kernelRetention.active = k
	}
	kernelRetention.Unlock()
	if retained {
		return nil, ErrRefused
	}
	for i, role := range []struct {
		path string
		kind int
	}{
		{"/proc/thread-self/ns/net", unix.CLONE_NEWNET}, {"/proc/thread-self/ns/mnt", unix.CLONE_NEWNS},
	} {
		k.phase = "namespace"
		fd, err := unix.Open(role.path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			return fail()
		}
		file := os.NewFile(uintptr(fd), "nfs-fixture-original-namespace")
		if i == 0 {
			k.network = file
		} else {
			k.mounts = file
		}
		var fs unix.Statfs_t
		kind, err := unix.IoctlRetInt(fd, unix.NS_GET_NSTYPE)
		if err != nil || kind != role.kind || unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.NSFS_MAGIC || unix.Fstat(fd, &k.ns[i]) != nil || k.ns[i].Ino == 0 {
			return fail()
		}
	}
	k.phase = "control-root"
	fd, err := unix.Open("/proc/fs/nfsd", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fail()
	}
	k.directory = os.NewFile(uintptr(fd), "nfs-fixture-original-control")
	var fs unix.Statfs_t
	// Linux6.18.55 fs/nfsd/nfsctl.c nfsd_fill_super uses this literal.
	if unix.Fstatfs(fd, &fs) != nil || fs.Type != 0x6e667364 || nfsKernelStat(fd, "", unix.AT_EMPTY_PATH, &k.root) != nil || k.check(ctx) != nil {
		return fail()
	}
	return k, nil
}

const nfsKernelStatMask = unix.STATX_TYPE | unix.STATX_INO | unix.STATX_MNT_ID_UNIQUE | unix.STATX_UID | unix.STATX_GID

func nfsKernelStat(fd int, name string, flags int, x *unix.Statx_t) error {
	if unix.Statx(fd, name, flags|unix.AT_NO_AUTOMOUNT|unix.AT_SYMLINK_NOFOLLOW, nfsKernelStatMask, x) != nil || x.Mask&nfsKernelStatMask != nfsKernelStatMask || x.Ino == 0 || x.Mnt_id == 0 || x.Uid != 0 || x.Gid != 0 {
		return ErrRefused
	}
	return nil
}
func sameNFSKernelObject(a, b unix.Statx_t) bool {
	return a.Mnt_id == b.Mnt_id && a.Ino == b.Ino && a.Dev_major == b.Dev_major && a.Dev_minor == b.Dev_minor && a.Mode&unix.S_IFMT == b.Mode&unix.S_IFMT
}

// Caller holds one OS thread and the lifetime gate for every complete operation.
func (k *ControllerQEMU) check(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || k.directory == nil || k.network == nil || k.mounts == nil {
		return ErrRefused
	}
	var held, path unix.Statx_t
	if nfsKernelStat(int(k.directory.Fd()), "", unix.AT_EMPTY_PATH, &held) != nil || nfsKernelStat(unix.AT_FDCWD, "/proc/fs/nfsd", 0, &path) != nil || held.Mode&unix.S_IFMT != unix.S_IFDIR || !sameNFSKernelObject(held, k.root) || !sameNFSKernelObject(path, k.root) {
		return ErrRefused
	}
	for i, role := range []struct {
		file *os.File
		path string
	}{{k.network, "/proc/thread-self/ns/net"}, {k.mounts, "/proc/thread-self/ns/mnt"}} {
		var held, current unix.Stat_t
		if unix.Fstat(int(role.file.Fd()), &held) != nil || unix.Stat(role.path, &current) != nil || held.Dev != k.ns[i].Dev || held.Ino != k.ns[i].Ino || current.Dev != held.Dev || current.Ino != held.Ino {
			return ErrRefused
		}
	}
	return nil
}

func (k *ControllerQEMU) enter(ctx context.Context, cleanup bool) error {
	if k == nil || k.original != k || k.gate == nil || ctx == nil || ctx.Err() != nil {
		return ErrRefused
	}
	select {
	case k.gate <- struct{}{}:
	default:
		return ErrRefused
	}
	runtime.LockOSThread()
	if k.closed || k.review && !cleanup || k.check(ctx) != nil {
		k.retain()
		k.leave()
		return ErrRefused
	}
	return nil
}
func (k *ControllerQEMU) leave() { runtime.UnlockOSThread(); <-k.gate }

// Each transaction uses a NEW open relative to the held original filesystem.
// Seeking/reusing a legacy transaction descriptor would read stale snapshots.
func (k *ControllerQEMU) transaction(ctx context.Context, name string, input []byte) ([]byte, error) {
	if name != "threads" && name != "versions" && name != "portlist" || k.check(ctx) != nil {
		return nil, k.retain()
	}
	flags := unix.O_RDONLY
	if input != nil {
		flags = unix.O_WRONLY
	}
	fd, err := unix.Openat2(int(k.directory.Fd()), name, &unix.OpenHow{Flags: uint64(flags | unix.O_CLOEXEC | unix.O_NOFOLLOW), Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV})
	if err != nil {
		return nil, k.retain()
	}
	f := os.NewFile(uintptr(fd), "nfs-fixture-control-transaction")
	var st unix.Statx_t
	var data []byte
	if nfsKernelStat(fd, "", unix.AT_EMPTY_PATH, &st) != nil || st.Mnt_id != k.root.Mnt_id || st.Mode&unix.S_IFMT != unix.S_IFREG {
		err = ErrRefused
	} else if input == nil {
		data, err = io.ReadAll(io.LimitReader(f, 4097))
		if len(data) > 4096 {
			err = ErrRefused
		}
	} else {
		var n int
		n, err = f.Write(input)
		if n != len(input) {
			err = ErrRefused
		}
	}
	// A failed Close is never repeated, including during later cleanup.
	if f.Close() != nil {
		k.uncertain = f
		err = ErrRefused
	}
	if err != nil || k.check(ctx) != nil {
		return nil, k.retain()
	}
	return data, nil
}
func (k *ControllerQEMU) profile(ctx context.Context, running bool) error {
	var values [3][]byte
	for i, name := range []string{"threads", "versions", "portlist"} {
		v, err := k.transaction(ctx, name, nil)
		if err != nil {
			return err
		}
		values[i] = v
	}
	if ValidateProfileQEMU(values[0], values[1], values[2], running) != nil {
		return k.retain()
	}
	return nil
}

func (k *ControllerQEMU) Start(ctx context.Context) error {
	if err := k.enter(ctx, false); err != nil {
		return err
	}
	defer k.leave()
	k.phase = "initial-profile"
	if k.started || k.stopped || k.profile(ctx, false) != nil {
		return k.retain()
	}
	k.phase = "socket"
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
	if err != nil {
		return k.retain()
	}
	k.socket = fd
	k.socketIdentity, err = readNFSSocketIdentityQEMU(fd)
	if err != nil {
		return k.retain()
	}
	k.phase = "bind-socket"
	if err := unix.Bind(fd, &unix.SockaddrInet4{Port: 2049, Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		if errors.Is(err, unix.EADDRINUSE) {
			k.unattached = &unattachedSocketQEMU{bindCause: err}
		}
		return errors.Join(k.retain(), err)
	}
	k.phase = "listen-socket"
	if err := unix.Listen(fd, 64); err != nil {
		return errors.Join(k.retain(), err)
	}
	if checkNFSSocketQEMU(fd, k.socketIdentity) != nil {
		return k.retain()
	}
	request, err := SocketRequestQEMU(fd)
	if err != nil {
		return k.retain()
	}
	k.started = true // Before a possibly partially successful kernel transaction.
	k.phase = "attach-listener"
	if _, err := k.transaction(ctx, "portlist", request); err != nil {
		return err
	}
	k.phase = "start-threads"
	if _, err := k.transaction(ctx, "threads", []byte("2\n")); err != nil {
		return err
	}
	k.phase = "running-profile"
	if k.profile(ctx, true) != nil || checkNFSSocketQEMU(fd, k.socketIdentity) != nil {
		return k.retain()
	}
	return nil
}

func (k *ControllerQEMU) Stop(ctx context.Context) error {
	if err := k.enter(ctx, true); err != nil {
		return err
	}
	defer k.leave()
	if k.unattached != nil {
		return k.stopUnattachedSocketQEMU(ctx)
	}
	if !k.started || k.stopped || k.socket < 0 || !matchesNFSSocketIdentityQEMU(k.socket, k.socketIdentity) {
		return k.retain()
	}
	k.stopped = true // One attempt only, including errors/cancellation.
	k.phase = "stop-threads"
	if _, err := k.transaction(ctx, "threads", []byte("0\n")); err != nil {
		return err
	}
	if k.socket >= 0 {
		k.phase = "socket-close"
		if !matchesNFSSocketIdentityQEMU(k.socket, k.socketIdentity) {
			return k.retain()
		}
		fd := k.socket
		k.socket = -1
		if unix.Close(fd) != nil {
			return k.retain()
		}
	}
	k.phase = "stopped-profile"
	if k.profile(ctx, false) != nil || k.review {
		return k.retain()
	}
	return nil
}

func (k *ControllerQEMU) Close(ctx context.Context) error {
	if err := k.enter(ctx, false); err != nil {
		return err
	}
	defer k.leave()
	k.phase = "closing-profile"
	if !k.stopped || k.socket >= 0 || k.uncertain != nil || k.profile(ctx, false) != nil {
		return k.retain()
	}
	for _, slot := range []**os.File{&k.directory, &k.mounts, &k.network} {
		k.phase = "close-inputs"
		f := *slot
		*slot = nil
		if f.Close() != nil {
			k.uncertain = f
			return k.retain()
		}
	}
	k.closed = true
	return nil
}

// OpenCodeQEMU admits only the explicit NIC-less code/userspace fixture.
func OpenCodeQEMU(ctx context.Context) (*ControllerQEMU, error) { return openQEMU(ctx, false) }

// OpenRebootQEMU additionally requires the fixed state-reboot boot selector.
// Its trusted main-package caller MUST retain the original synthetic-disk guard.
func OpenRebootQEMU(ctx context.Context) (*ControllerQEMU, error) { return openQEMU(ctx, true) }

func fixtureGuardQEMU(reboot bool) bool {
	if runtime.GOARCH != "arm" || os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 {
		return false
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return false
	}
	arm5 := false
	for _, setting := range info.Settings {
		if setting.Key == "GOARM" {
			arm5 = strings.Split(setting.Value, ",")[0] == "5"
		}
	}
	if !arm5 {
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
	codes, states := 0, 0
	for _, word := range strings.Fields(string(command)) {
		if word == "phantowd_nfs_code_fixture=1" {
			codes++
		}
		if strings.HasPrefix(word, "phantowd.state=") {
			if word != "phantowd.state=seed" && word != "phantowd.state=verify" {
				return false
			}
			states++
		}
	}
	return (!reboot && codes == 1 && states == 0) || (reboot && states == 1 && codes == 0)
}

// CheckRunning rechecks the original control/namespace authority, exact legacy
// profile and the actual retained IPv4 loopback listening socket. It is not a
// complete kernel export/cache/client census or atomic product-domain lease.
func (k *ControllerQEMU) CheckRunning(ctx context.Context) error {
	if err := k.enter(ctx, false); err != nil {
		return err
	}
	defer k.leave()
	k.phase = "check-running"
	if !k.started || k.stopped || k.socket < 0 || k.profile(ctx, true) != nil {
		return k.retain()
	}
	if checkNFSSocketQEMU(k.socket, k.socketIdentity) != nil || k.check(ctx) != nil {
		return k.retain()
	}
	return nil
}

// CheckPreparedQEMU observes an ORIGINAL reserved but never-started controller.
// No transaction writes, stop, close, release or replacement are performed.
// It is not sole kernel-domain authority or complete client quiescence.
func (k *ControllerQEMU) CheckPreparedQEMU(ctx context.Context) error {
	if err := k.enter(ctx, false); err != nil {
		return err
	}
	defer k.leave()
	if k.started || k.stopped || k.socket >= 0 || k.uncertain != nil {
		return ErrRefused
	}
	kernelRetention.Lock()
	originalReservation := kernelRetention.active == k && len(kernelRetention.objects) == 0
	kernelRetention.Unlock()
	if !originalReservation {
		return k.retain()
	}
	k.phase = "check-prepared"
	if k.profile(ctx, false) != nil {
		return k.retain()
	}
	return ctx.Err()
}

// CheckStopped observes the ORIGINAL stopped component without releasing any
// namespace/control reference. It is not complete export/client quiescence.
func (k *ControllerQEMU) CheckStopped(ctx context.Context) error {
	if err := k.enter(ctx, false); err != nil {
		return err
	}
	defer k.leave()
	k.phase = "check-stopped"
	if !k.started || !k.stopped || k.socket >= 0 || k.uncertain != nil || k.profile(ctx, false) != nil {
		return k.retain()
	}
	return nil
}

func (ControllerQEMU) MarshalJSON() ([]byte, error) { return nil, ErrRefused }
func (*ControllerQEMU) UnmarshalJSON([]byte) error  { return ErrRefused }
func (ControllerQEMU) Format(s fmt.State, _ rune)   { _, _ = io.WriteString(s, "nfs-kernel{private}") }
