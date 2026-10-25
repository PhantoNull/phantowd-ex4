//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/nfskernel"
)

// Fixed, explicit disposable-guest activation. No user policy or physical media.
// The retained controller, not rpc.nfsd or this harness, owns NFSD's listener
// and thread transactions. Helpers and the actual client are tested around it.
func runQEMUNFSKernelActivation() error {
	// Two explicit lifetimes, never a retry after failure. The second client
	// must read bytes written before the first verified stop and close.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var previous *nfskernel.ControllerQEMU
	for cycle := 1; cycle <= 2; cycle++ {
		if err := runQEMUNFSKernelCycle(ctx, cycle, &previous); err != nil {
			return fmt.Errorf("NFS cycle=%d: %w", cycle, err)
		}
		fmt.Printf("PHANTOWD_NFS_KERNEL_CYCLE_DONE cycle=%d\n", cycle)
	}
	fmt.Println("PHANTOWD_NFS_KERNEL_RESTART_READY cycles=2 kernel_backend=true activation=true persisted_bytes=true closed_handles=inert teardown=clean scope=qemu-loopback-only")
	fmt.Println("PHANTOWD_NFS_KERNEL_READY kernel_backend=true activation=true protocol=nfs3 transport=tcp read=true write=true teardown=clean scope=qemu-loopback-only")
	return nil
}

func runQEMUNFSKernelCycle(ctx context.Context, cycle int, previous **nfskernel.ControllerQEMU) error {
	const payload = "retained-controller-nfs3-tcp-write\n"
	k, err := nfskernel.OpenSmokeQEMU(ctx)
	if err != nil {
		return fmt.Errorf("kernel-open: %w", err)
	}
	command := func(name string, args ...string) error {
		deadline, done := context.WithTimeout(ctx, 10*time.Second)
		defer done()
		out, err := exec.CommandContext(deadline, name, args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s: %w: %s", name, err, out)
		}
		return nil
	}
	phase := func(label string, err error) error {
		if err != nil {
			return fmt.Errorf("NFS activation phase=%s: %w", label, err)
		}
		fmt.Println("PHANTOWD_NFS_KERNEL_PHASE phase=" + label)
		return nil
	}
	if *previous != nil {
		old := *previous
		for _, call := range []func(context.Context) error{old.Start, old.Stop, old.Close, old.CheckRunning, old.CheckStopped, old.CheckPreparedQEMU} {
			if !errors.Is(call(ctx), nfskernel.ErrRefused) {
				return phase("closed-handle", errors.New("closed controller admitted an operation"))
			}
		}
	}
	if err := phase("prepared", k.CheckPreparedQEMU(ctx)); err != nil {
		return err
	}
	for _, dir := range []string{"/run/rpcbind", "/run/nfs", "/run/phantowd-nfs-kernel-client"} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return phase("runtime-directories", err)
		}
	}
	// A foreground child is reaped exactly once; cleanup also runs on failure.
	start := func(path string, args ...string) (func() error, error) {
		cmd := exec.CommandContext(ctx, path, args...)
		cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
		if err := cmd.Start(); err != nil {
			return nil, err
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		stopped := false
		return func() error {
			if stopped {
				return nil
			}
			stopped = true
			if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
				return err
			}
			select {
			case err := <-done:
				var exit *exec.ExitError
				if err == nil || errors.As(err, &exit) && exit.ProcessState.Sys().(syscall.WaitStatus).Signal() == syscall.SIGTERM {
					return nil
				}
				return err
			case <-time.After(5 * time.Second):
				_ = cmd.Process.Kill()
				<-done
				return errors.New("foreground helper did not stop gracefully")
			}
		}, nil
	}
	stopRPC, err := start("/usr/sbin/rpcbind", "-f", "-h", "127.0.0.1")
	if err != nil {
		return phase("rpcbind-start", err)
	}
	defer stopRPC() // Failure never emits READY, even if cleanup succeeds.
	ready := func(program, version string) error {
		var last error
		for i := 0; i < 20; i++ {
			last = command("/usr/bin/rpcinfo", "-T", "tcp", "127.0.0.1", program, version)
			if last == nil {
				return nil
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(100 * time.Millisecond):
			}
		}
		return last
	}
	if err := phase("rpcbind-ready", ready("100000", "4")); err != nil {
		return err
	}
	if err := phase("controller-start", k.Start(ctx)); err != nil {
		return err
	}
	stopMountd, err := start("/usr/sbin/rpc.mountd", "-F", "-N", "2", "-N", "4", "-V", "3", "-p", "20048")
	if err != nil {
		return phase("mountd-start", err)
	}
	defer stopMountd()
	if err := phase("mountd-ready", ready("100005", "3")); err != nil {
		return err
	}
	const server = "/srv/phantowd-nfs-smoke"
	const client = "/run/phantowd-nfs-kernel-client"
	const export = "127.0.0.1:" + server
	if err := os.Chown(server, 65534, 65534); err != nil {
		return phase("fixture-owner", err)
	}
	if err := phase("export", command("/usr/sbin/exportfs", "-i", "-o", "rw,sync,no_subtree_check,all_squash,anonuid=65534,anongid=65534", export)); err != nil {
		return err
	}
	if err := phase("client-mount", command("/bin/mount", "-t", "nfs", "-o", "vers=3,proto=tcp,nolock,soft,timeo=5,retrans=1", export, client)); err != nil {
		return err
	}
	mounts, err := os.ReadFile("/proc/mounts")
	matching := 0
	for _, line := range strings.Split(string(mounts), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 6 || fields[1] != client {
			continue
		}
		options := "," + fields[3] + ","
		if fields[0] == export && fields[2] == "nfs" && strings.Contains(options, ",vers=3,") && strings.Contains(options, ",proto=tcp,") {
			matching++
		}
	}
	if err != nil || matching != 1 {
		return phase("client-options", errors.New("exact NFSv3/TCP mount observation missing"))
	}
	data, err := os.ReadFile(client + "/marker")
	if err != nil || !bytes.Equal(data, []byte("phantowd-qemu-nfs-smoke-v1\n")) {
		return phase("client-read", errors.New("server marker read differs"))
	}
	if cycle == 2 {
		data, err := os.ReadFile(client + "/controller-write-1")
		if err != nil || !bytes.Equal(data, []byte(payload)) {
			return phase("previous-cycle-bytes", errors.New("previous client write did not survive service restart"))
		}
	}
	writeName := fmt.Sprintf("/controller-write-%d", cycle)
	f, err := os.OpenFile(client+writeName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return phase("client-write-open", err)
	}
	n, writeErr := f.WriteString(payload)
	syncErr, closeErr := f.Sync(), f.Close()
	if n != len(payload) || writeErr != nil || syncErr != nil || closeErr != nil {
		return phase("client-write-sync-close", errors.Join(writeErr, syncErr, closeErr, errors.New("write completion uncertain")))
	}
	for _, path := range []string{client + writeName, server + writeName} {
		data, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(data, []byte(payload)) {
			return phase("client-server-bytes", errors.New("written bytes differ"))
		}
	}
	if err := phase("running-after-io", k.CheckRunning(ctx)); err != nil {
		return err
	}
	if err := phase("client-unmount", command("/bin/umount", client)); err != nil {
		return err
	}
	mounts, err = os.ReadFile("/proc/mounts")
	if err != nil || strings.Contains(string(mounts), " "+client+" ") {
		return phase("client-gone", errors.New("mount still observed or unreadable"))
	}
	if err := phase("unexport", command("/usr/sbin/exportfs", "-u", export)); err != nil {
		return err
	}
	if err := phase("controller-stop", k.Stop(ctx)); err != nil {
		return err
	}
	if err := phase("controller-stopped", k.CheckStopped(ctx)); err != nil {
		return err
	}
	if err := phase("mountd-stop", stopMountd()); err != nil {
		return err
	}
	if err := phase("rpcbind-stop", stopRPC()); err != nil {
		return err
	}
	if err := phase("controller-close", k.Close(ctx)); err != nil {
		return err
	}
	*previous = k
	return nil
}
