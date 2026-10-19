//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const nfsRebootRuntime = "/run/phantowd-nfs-reboot"
const nfsRebootAnchor = "/srv/phantowd/volumes/" + qemuNFSVolumeID
const nfsRebootPayload = "persistent-qemu-nfs-data\n"

// Exact disposable-kernel profile, not a product census or stop/lease proof.
// The pinned guest has CONFIG_NFSD_V2 and CONFIG_NFSD_V4 disabled; kernel
// svc_one_xprt_name reports transport/port, not listener address or family.
func validateQEMUNFSKernelProfile(threads, versions, ports []byte, running bool) error {
	wantThreads, wantPorts := "0\n", ""
	if running {
		wantThreads, wantPorts = "2\n", "tcp 2049\n"
	}
	if !bytes.Equal(threads, []byte(wantThreads)) || !bytes.Equal(versions, []byte("+3\n")) ||
		!bytes.Equal(ports, []byte(wantPorts)) {
		return errors.New("NFS reboot kernel profile mismatch")
	}
	return nil
}

func checkQEMUNFSKernelProfile(running bool) error {
	var values [3][]byte
	for index, name := range []string{"threads", "versions", "portlist"} {
		file, err := os.Open("/proc/fs/nfsd/" + name)
		if err != nil {
			return err
		}
		// The pinned kernel uses a bounded transaction buffer. Detect excess
		// rather than silently interpreting a truncated observation.
		values[index], err = io.ReadAll(io.LimitReader(file, 4097))
		if err = errors.Join(err, file.Close()); err != nil {
			return err
		}
	}
	if err := validateQEMUNFSKernelProfile(values[0], values[1], values[2], running); err != nil {
		return err
	}
	return checkQEMUNFSNetlinkProfile(running)
}

type nfsRebootDaemon struct {
	command *exec.Cmd
	done    <-chan error
}

// Only the NIC-less two-kernel harness calls this fixture, after the original
// state disk has been qualified and mounted. This is not product boot wiring.
func exerciseQEMUNFSReboot(phase string) (result error) {
	if phase != "seed" && phase != "verify" {
		return errors.New("unknown NFS reboot phase")
	}
	if os.Geteuid() != 0 {
		return errors.New("NFS reboot fixture requires guest root")
	}
	if err := runQEMUNFSTest("verify-disk"); err != nil {
		return err
	}
	device, err := os.ReadFile("/sys/class/block/sdb/dev")
	if err != nil {
		return err
	}
	mounts, err := collectMountInventory(os.DirFS("/proc"), time.Now())
	if err != nil {
		return err
	}
	found := false
	for _, mount := range mounts.Mounts {
		if mount.MountPoint == qemuStateAnchor && !mount.ReadOnly && mount.Filesystem == "ext4" &&
			fmt.Sprintf("%d:%d", mount.DeviceMajor, mount.DeviceMinor) == strings.TrimSpace(string(device)) {
			found = true
		}
		if mount.MountPoint == "/proc/fs/nfsd" || mount.MountPoint == "/srv/phantowd/volumes" ||
			strings.HasPrefix(mount.MountPoint, "/srv/phantowd/volumes/") {
			return errors.New("NFS reboot fixture requires unused guest mounts")
		}
	}
	if !found {
		return errors.New("NFS reboot fixture state mount missing")
	}
	if entries, err := os.ReadDir("/etc/exports.d"); (err != nil && !errors.Is(err, os.ErrNotExist)) || len(entries) != 0 {
		return errors.New("NFS reboot fixture requires an empty exports.d")
	}
	policy, err := prepareQEMUNFSRebootPolicy(qemuStateAnchor, phase)
	if err != nil {
		return err
	}
	retainPolicy, kernelSettled := false, false
	var inode uint64
	var policyHash, dataHash [32]byte
	bootID, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return errors.Join(err, policy.Close())
	}
	defer func() {
		if retainPolicy {
			qemuNFSKernelRetention.Lock()
			qemuNFSKernelRetention.policies = append(qemuNFSKernelRetention.policies, policy)
			qemuNFSKernelRetention.Unlock()
			result = errors.Join(result, errQEMUNFSKernel)
			return
		}
		result = errors.Join(result, policy.Check(), policy.Close())
		if !kernelSettled {
			result = errors.Join(result, errQEMUNFSKernel)
		}
		if result == nil {
			fmt.Printf("PHANTOWD_NFS_REBOOT_PHASE_READY phase=%s boot_id=%s policy_sha256=%x inode=%d data_sha256=%x rw=true ro_denied=true client_denied=true uid=101000 gid=101000 kernel_profile=v3-tcp-only kernel_stopped=true fsid_rebind_refused=true listener_identity=true retained_kernel=true teardown=true scope=clean-qemu-reboot-only\n",
				phase, strings.TrimSpace(string(bootID)), policyHash, inode, dataHash)
		}
	}()
	if err := verifyQEMUNFSRebootBindingRefusal(policy); err != nil {
		return err
	}
	data := qemuStateAnchor + "/nfs-reboot/data"
	if err := prepareQEMUNFSRebootData(data, phase); err != nil {
		return err
	}
	for _, path := range []string{nfsRebootRuntime, nfsRebootRuntime + "/rw-client", nfsRebootRuntime + "/ro-client", nfsRebootRuntime + "/denied-client", "/run/nfs"} {
		if err := os.Mkdir(path, 0700); err != nil {
			return err
		}
	}
	for _, name := range []string{"etab", "rmtab"} {
		if err := writeQEMUStateFixture("/run/nfs/"+name, nil); err != nil {
			return err
		}
	}
	var ownedMounts, clientMounts []string
	var daemons []nfsRebootDaemon
	exportsLoaded := false
	var kernel *qemuNFSKernel
	defer func() {
		// Only this fresh, NIC-less guest's known resources. No lazy/forced
		// unmount, global host operation or retry after uncertain teardown.
		for i := len(clientMounts) - 1; i >= 0; i-- {
			result = errors.Join(result, unix.Unmount(clientMounts[i], 0))
		}
		if exportsLoaded {
			_, err := nfsRebootCommand("/usr/sbin/exportfs", "-au")
			result = errors.Join(result, err)
			_, err = nfsRebootCommand("/usr/sbin/exportfs", "-f")
			result = errors.Join(result, err)
			remaining, err := nfsRebootCommand("/usr/sbin/exportfs", "-s")
			if err != nil || len(bytes.TrimSpace(remaining)) != 0 {
				result = errors.Join(result, errors.New("NFS reboot exports not withdrawn"), err)
			}
		}
		if kernel != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			result = errors.Join(result, kernel.Stop(ctx))
			cancel()
		}
		for i := len(daemons) - 1; i >= 0; i-- {
			result = errors.Join(result, stopQEMURebootDaemon(daemons[i].command, daemons[i].done))
		}
		if kernel != nil {
			result = errors.Join(result, checkQEMUNFSKernelProfile(false))
		}
		if result != nil {
			retainPolicy = true
			return
		}
		if kernel != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			result = errors.Join(result, kernel.Close(ctx))
			cancel()
			if result != nil {
				retainPolicy = true
				return
			}
			kernelSettled = true
		}
		for i := len(ownedMounts) - 1; i >= 0; i-- {
			if err := unix.Unmount(ownedMounts[i], 0); err != nil {
				result = errors.Join(result, fmt.Errorf("NFS reboot unmount %s: %w", ownedMounts[i], err))
			}
		}
		if result != nil {
			retainPolicy = true
		}
	}()
	mount := func(source, target, filesystem string, flags uintptr, options string) error {
		if err := unix.Mount(source, target, filesystem, flags, options); err != nil {
			return err
		}
		ownedMounts = append(ownedMounts, target)
		return nil
	}
	if err := mount("tmpfs", "/srv/phantowd/volumes", "tmpfs", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "mode=0755,size=1m"); err != nil {
		return err
	}
	if err := os.Mkdir(nfsRebootAnchor, 0755); err != nil {
		return err
	}
	if err := mount(data, nfsRebootAnchor, "", unix.MS_BIND, ""); err != nil {
		return err
	}
	if err := writeQEMUStateFixture(nfsRebootRuntime+"/exports", []byte(policy.Table)); err != nil {
		return err
	}
	if err := mount(nfsRebootRuntime+"/exports", "/etc/exports", "", unix.MS_BIND, ""); err != nil {
		return err
	}
	if err := mount("nfsd", "/proc/fs/nfsd", "nfsd", 0, ""); err != nil {
		return err
	}
	if err := checkQEMUNFSKernelProfile(false); err != nil {
		return err
	}
	active, err := nfsRebootCommand("/usr/sbin/exportfs", "-s")
	if err != nil || len(bytes.TrimSpace(active)) != 0 {
		return errors.New("NFS reboot fixture found existing exports")
	}
	start := func(program, address string, args ...string) error {
		command := exec.Command(program, args...)
		command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
		command.Stdout, command.Stderr = os.Stdout, os.Stderr
		command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if err := command.Start(); err != nil {
			return err
		}
		done := make(chan error, 1)
		go func() { done <- command.Wait() }()
		daemons = append(daemons, nfsRebootDaemon{command, done})
		// Startup readiness only: no service restart or mutation retry.
		for attempt := 0; attempt < 20; attempt++ {
			connection, err := net.DialTimeout("tcp", address, 50*time.Millisecond)
			if err == nil {
				return connection.Close()
			}
			time.Sleep(50 * time.Millisecond)
		}
		return errors.New("NFS reboot foreground daemon did not become ready")
	}
	if err := policy.Check(); err != nil {
		return err
	}
	if err := start("/usr/sbin/rpcbind", "127.0.0.1:111", "-f"); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	kernel, err = openQEMUNFSKernel(ctx)
	if err != nil {
		return err
	}
	if err := kernel.Start(ctx); err != nil {
		return err
	}
	if err := start("/usr/sbin/rpc.mountd", "127.0.0.1:20048", "-F", "-N", "2", "-N", "4", "-V", "3", "-u", "-p", "20048"); err != nil {
		return err
	}
	exportsLoaded = true
	if _, err := nfsRebootCommand("/usr/sbin/exportfs", "-r"); err != nil {
		return err
	}
	if err := checkQEMUNFSKernelProfile(true); err != nil {
		return err
	}
	for _, spec := range []struct{ relative, client string }{{qemuNFSWritablePath, "rw-client"}, {"read-only", "ro-client"}, {"denied-client", "denied-client"}} {
		target := nfsRebootRuntime + "/" + spec.client
		output, err := nfsRebootCommand("/sbin/mount.nfs", "127.0.0.1:"+nfsRebootAnchor+"/"+spec.relative, target,
			"-o", "vers=3,proto=tcp,sec=sys,nolock,rw,soft,timeo=5,retrans=1,retry=0")
		if err == nil {
			clientMounts = append(clientMounts, target)
		}
		if spec.client == "denied-client" {
			var exit *exec.ExitError
			if !errors.As(err, &exit) || !strings.Contains(string(output), "access denied by server") {
				return fmt.Errorf("NFS reboot denied-client decision not verified: %s (%v)", output, err)
			}
		} else if err != nil {
			return err
		}
	}
	inode, dataHash, err = exerciseQEMUNFSRebootIO(phase)
	if err != nil {
		return err
	}
	if err := checkQEMUNFSKernelProfile(true); err != nil {
		return err
	}
	current, err := os.ReadFile(qemuStateAnchor + "/nfs-reboot/policy/nas-services.json")
	if err != nil {
		return err
	}
	policyHash = sha256.Sum256(current)
	// Only this generated virtual medium; this is clean shutdown, not power loss.
	file, err := os.Open(data)
	if err != nil {
		return err
	}
	err = unix.Syncfs(int(file.Fd()))
	return errors.Join(err, file.Close())
}

func nfsRebootCommand(program string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, program, args...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	command.WaitDelay = time.Second
	output, err := command.CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("NFS reboot %s: %s: %w", filepath.Base(program), bytes.TrimSpace(output), err)
	}
	return output, nil
}

func prepareQEMUNFSRebootData(root, phase string) error {
	if phase == "seed" {
		if err := os.Mkdir(root, 0755); err != nil {
			return err
		}
		for _, name := range []string{qemuNFSWritablePath, "read-only", "denied-client"} {
			if err := os.Mkdir(root+"/"+name, 0770); err != nil {
				return err
			}
			if err := os.Chown(root+"/"+name, 101000, 101000); err != nil {
				return err
			}
			if err := os.Chmod(root+"/"+name, 0770); err != nil {
				return err
			}
		}
		if err := writeQEMUStateFixture(root+"/read-only/marker", []byte("phantowd-nfs-reboot-ro\n")); err != nil {
			return err
		}
		if err := os.Chown(root+"/read-only/marker", 101000, 101000); err != nil {
			return err
		}
	}
	for _, name := range []string{qemuNFSWritablePath, "read-only", "denied-client"} {
		var st unix.Stat_t
		if err := unix.Lstat(root+"/"+name, &st); err != nil || st.Mode != unix.S_IFDIR|0770 || st.Uid != 101000 || st.Gid != 101000 {
			return errors.New("NFS reboot data directory not retained")
		}
	}
	return nil
}

func exerciseQEMUNFSRebootIO(phase string) (uint64, [32]byte, error) {
	var zero [32]byte
	created := "original"
	if phase == "verify" {
		// Read the original BEFORE creating any new file; never repair/recreate it.
		if data, err := os.ReadFile(nfsRebootRuntime + "/rw-client/original"); err != nil || string(data) != nfsRebootPayload {
			return 0, zero, errors.New("NFS reboot original client data not retained")
		}
		created = "after-reboot"
	}
	file, err := os.OpenFile(nfsRebootRuntime+"/rw-client/"+created, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return 0, zero, err
	}
	_, writeErr := file.WriteString(nfsRebootPayload)
	err = errors.Join(writeErr, file.Sync(), file.Close())
	if err != nil {
		return 0, zero, err
	}
	var original uint64
	for _, name := range []string{"original", created} {
		path := nfsRebootAnchor + "/" + qemuNFSWritablePath + "/" + name
		data, err := os.ReadFile(path)
		var st unix.Stat_t
		if err != nil || string(data) != nfsRebootPayload || unix.Lstat(path, &st) != nil ||
			st.Mode != unix.S_IFREG|0600 || st.Uid != 101000 || st.Gid != 101000 {
			return 0, zero, errors.New("NFS reboot server data/ownership mismatch")
		}
		if name == "original" {
			original = st.Ino
		}
	}
	if data, err := os.ReadFile(nfsRebootRuntime + "/ro-client/marker"); err != nil || string(data) != "phantowd-nfs-reboot-ro\n" {
		return 0, zero, errors.New("NFS reboot read-only client read failed")
	}
	file, err = os.OpenFile(nfsRebootRuntime+"/ro-client/must-not-exist", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if file != nil {
		_ = file.Close()
	}
	if !errors.Is(err, syscall.EROFS) {
		return 0, zero, errors.New("NFS reboot read-only export did not return EROFS")
	}
	if _, err := os.Lstat(nfsRebootAnchor + "/read-only/must-not-exist"); !errors.Is(err, os.ErrNotExist) {
		return 0, zero, errors.New("NFS reboot denied write left server data")
	}
	return original, sha256.Sum256([]byte(nfsRebootPayload)), nil
}
