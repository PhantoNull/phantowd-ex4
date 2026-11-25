//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package nfskernel

import (
	"context"
	"os"
	"runtime"
	"runtime/debug"
	"strings"

	"golang.org/x/sys/unix"
)

type ControllerQEMU = Controller

func SocketRequestQEMU(fd int) ([]byte, error) { return socketRequest(fd) }

func openQEMU(ctx context.Context, role string) (*ControllerQEMU, error) {
	if ctx == nil || ctx.Err() != nil || !fixtureGuardQEMU(role) {
		return nil, ErrRefused
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	k := &ControllerQEMU{gate: make(chan struct{}, 1), socket: -1, phase: "open"}
	k.address = [4]byte{127, 0, 0, 1}
	if role == "peer" {
		k.address = [4]byte{} // Fixed isolated two-guest fixture; never a caller-selected address.
	}
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

// OpenCodeQEMU admits only the explicit NIC-less code/userspace fixture.
func OpenCodeQEMU(ctx context.Context) (*ControllerQEMU, error) { return openQEMU(ctx, "code") }

// OpenRebootQEMU additionally requires the fixed state-reboot boot selector.
// Its trusted main-package caller MUST retain the original synthetic-disk guard.
func OpenRebootQEMU(ctx context.Context) (*ControllerQEMU, error) { return openQEMU(ctx, "reboot") }

// RebootFixtureQEMU checks the fixed role before fixture-only state preparation.
// This grants no controller, storage, policy or product admission authority.
func RebootFixtureQEMU() bool { return fixtureGuardQEMU("reboot") }

// OpenSmokeQEMU admits only the explicit disposable baseline smoke.
func OpenSmokeQEMU(ctx context.Context) (*ControllerQEMU, error) { return openQEMU(ctx, "smoke") }

func SmokeFixtureQEMU() bool { return fixtureGuardQEMU("smoke") }

func OpenPeerQEMU(ctx context.Context) (*ControllerQEMU, error) { return openQEMU(ctx, "peer") }
func PeerClientQEMU() bool                                      { return fixtureGuardQEMU("peer-client") }

func fixtureGuardQEMU(role string) bool {
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
	return err == nil && fixtureCommandQEMU(command, role)
}

func fixtureCommandQEMU(command []byte, role string) bool {
	if len(command) > 4096 {
		return false
	}
	codes, states, smokes := 0, 0, 0
	peers, peer := 0, ""
	for _, word := range strings.Fields(string(command)) {
		if strings.HasPrefix(word, "phantowd_nfs_peer=") {
			peer = strings.TrimPrefix(word, "phantowd_nfs_peer=")
			if peer != "server" && peer != "client" {
				return false
			}
			peers++
		}
		if strings.HasPrefix(word, "phantowd_nfs_kernel_smoke=") {
			if word != "phantowd_nfs_kernel_smoke=1" {
				return false
			}
			smokes++
		}
		if strings.HasPrefix(word, "phantowd_nfs_code_fixture=") {
			if word != "phantowd_nfs_code_fixture=1" {
				return false
			}
			codes++
		}
		if strings.HasPrefix(word, "phantowd.state=") {
			if word != "phantowd.state=seed" && word != "phantowd.state=verify" {
				return false
			}
			states++
		}
	}
	if peers != 0 {
		return peers == 1 && codes == 0 && states == 0 && smokes == 0 &&
			(role == "peer" && peer == "server" || role == "peer-client" && peer == "client")
	}
	return (role == "code" && codes == 1 && states == 0 && smokes == 0) ||
		(role == "reboot" && states == 1 && codes == 0 && smokes == 0) ||
		(role == "smoke" && smokes == 1 && codes == 0 && states == 0)
}
