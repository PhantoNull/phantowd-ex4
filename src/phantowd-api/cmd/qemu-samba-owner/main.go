//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Disposable owned-group composition proof, not the product Samba Owner.
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"golang.org/x/sys/unix"
)

const launcher = "/usr/sbin/phantowd-samba-root-launcher"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "PHANTOWD_SAMBA_OWNER_FAILED", err)
		os.Exit(1)
	}
}

func run() (result error) {
	model, err := os.ReadFile("/sys/firmware/devicetree/base/model")
	if err != nil || string(model) != "ARM Versatile PB\x00" || len(os.Args) != 1 ||
		os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 {
		return errors.New("fixture guard")
	}
	// A direct invocation must refuse before constructing any namespace/root.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	command := exec.CommandContext(ctx, launcher, "owned-server")
	output, err := command.CombinedOutput()
	cancel()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 ||
		string(output) != "PHANTOWD_SAMBA_ROOT_LAUNCH_REFUSED\n" {
		return errors.New("nonleader was not refused")
	}
	fd, err := unix.Open(launcher, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	input := os.NewFile(uintptr(fd), "fixture-helper")
	set, err := processowner.NewPinnedSet([]processowner.MemberSpec{{Name: "samba", Process: processowner.Spec{
		Executable: launcher, Args: []string{"owned-server"},
		RunAs: &processowner.Credentials{UID: 0, GID: 0},
		Ready: func(ctx context.Context) (bool, error) {
			_, err := client(ctx, "qpwriter", "ReadWrite", "ls")
			return err == nil, ctx.Err()
		},
		ReadyTimeout: 20 * time.Second, ProbeInterval: 200 * time.Millisecond, StopTimeout: 4 * time.Second,
	}}}, []*os.File{input})
	closeErr := input.Close()
	if err != nil {
		return errors.Join(err, closeErr)
	}
	defer func() {
		if set != nil {
			_, stopErr := set.Stop(context.Background())
			result = errors.Join(result, stopErr, set.Close())
		}
	}()
	if closeErr != nil {
		return closeErr
	}
	canceled, cancelStart := context.WithCancel(context.Background())
	cancelStart()
	before, err := set.Start(canceled)
	if !errors.Is(err, context.Canceled) || before.State == processowner.StateReady {
		return errors.New("canceled admission")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	started, err := set.Start(ctx)
	if err != nil || started.State != processowner.StateReady || len(started.Members) != 1 {
		return errors.Join(errors.New("owned readiness"), err)
	}
	pid := started.Members[0].Process.PID
	if err := verifyDaemon(pid); err != nil {
		return err
	}
	duplicate, err := set.Start(ctx)
	if !errors.Is(err, processowner.ErrAlreadyRunning) || duplicate.Members[0].Process.PID != pid ||
		!errors.Is(set.Close(), processowner.ErrAlreadyRunning) {
		return errors.New("live lifecycle refusal")
	}
	// Actual distinct-account access after readiness, not a pre-exec marker.
	const written = "/run/phantowd-samba-source/approved/owned-created"
	if _, err := os.Lstat(written); !errors.Is(err, os.ErrNotExist) {
		return errors.New("writer fixture is not fresh")
	}
	if _, err := client(ctx, "qpwriter", "ReadWrite", "put /run/upload owned-created"); err != nil {
		return errors.New("writer access")
	}
	var info unix.Stat_t
	if unix.Lstat(written, &info) != nil || info.Mode&unix.S_IFMT != unix.S_IFREG ||
		info.Uid != 1801 || info.Gid != 1800 || info.Mode&0007 != 0 {
		return errors.New("writer Unix ownership")
	}
	if _, err := client(ctx, "qpreader", "ReadWrite", "get owned-created /run/download"); err != nil {
		return errors.New("reader access")
	}
	wanted, err := os.ReadFile("/run/upload")
	if err != nil {
		return err
	}
	actual, err := os.ReadFile("/run/download")
	if err != nil || !bytes.Equal(wanted, actual) {
		return errors.New("reader bytes")
	}
	actual, err = os.ReadFile(written)
	if err != nil || !bytes.Equal(wanted, actual) {
		return errors.New("writer bytes")
	}
	for _, test := range []struct{ user, share, command, status string }{
		{"qpreader", "ReadWrite", "put /run/upload reader-denied", "NT_STATUS_ACCESS_DENIED"},
		{"qpoutsider", "ReadWrite", "ls", "NT_STATUS_ACCESS_DENIED"},
		{"qpwrong", "ReadWrite", "ls", "NT_STATUS_LOGON_FAILURE"},
		{"qpwriter", "KernelReadOnly", "put /run/upload owned-readonly-denied", "NT_STATUS_MEDIA_WRITE_PROTECTED"},
	} {
		output, err := client(ctx, test.user, test.share, test.command)
		if !errors.As(err, &exit) || exit.ExitCode() != 1 || !strings.Contains(string(output), test.status) {
			if len(output) > 512 {
				output = output[:512]
			}
			return fmt.Errorf("distinct-account denial %s/%s: exit=%v context=%v output=%q",
				test.user, test.share, err, ctx.Err(), output)
		}
	}
	if _, err := os.Lstat("/run/phantowd-samba-source/approved/reader-denied"); !errors.Is(err, os.ErrNotExist) {
		return errors.New("denied write effect")
	}
	if _, err := os.Lstat("/run/phantowd-samba-source/approved/owned-readonly-denied"); !errors.Is(err, os.ErrNotExist) {
		return errors.New("read-only write effect")
	}
	stopped, err := set.Stop(ctx)
	if err != nil || stopped.State != processowner.StateStopped || stopped.Members[0].Process.PID != 0 {
		return errors.Join(errors.New("owned stop"), err)
	}
	if err := unix.Kill(-pid, 0); !errors.Is(err, unix.ESRCH) {
		return errors.New("owned group remains")
	}
	if err := set.Close(); err != nil {
		return err
	}
	// No deferred Stop on a closed set. The verified explicit teardown is done.
	set = nil
	fmt.Println("PHANTOWD_SAMBA_OWNER_GROUP_READY nonleader_refused=true pinned_helper=true caller_close=true canceled_refused=true same_group=true caps=db distinct_accounts=true writer_bytes=true unix_ownership=true kernel_ro=true duplicate_refused=true live_close_refused=true stopped_reaped=true scope=qemu-only")
	return nil
}

func client(ctx context.Context, user, share, operation string) ([]byte, error) {
	bounded, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	return exec.CommandContext(bounded, launcher, "client", user, share, operation).CombinedOutput()
}

func verifyDaemon(pid int) error {
	if pid <= 1 {
		return errors.New("invalid owned pid")
	}
	group, err := unix.Getpgid(pid)
	if err != nil || group != pid {
		return errors.New("daemon escaped owned group")
	}
	base := "/proc/" + strconv.Itoa(pid)
	program, err := os.Readlink(base + "/exe")
	if err != nil || program != "/run/phantowd-samba-root/usr/sbin/smbd" {
		return errors.New("actual daemon exec")
	}
	root, err := os.Readlink(base + "/root")
	if err != nil || root != "/run/phantowd-samba-root" {
		return errors.New("actual restricted root")
	}
	childNS, err := os.Readlink(base + "/ns/mnt")
	if err != nil {
		return err
	}
	parentNS, err := os.Readlink("/proc/self/ns/mnt")
	if err != nil || parentNS == childNS {
		return errors.New("namespace not private")
	}
	status, err := os.ReadFile(base + "/status")
	if err != nil || len(status) > 64<<10 {
		return errors.New("daemon authority evidence")
	}
	required := map[string]string{
		"CapEff:": "00000000000000db", "CapPrm:": "00000000000000db", "CapBnd:": "00000000000000db",
		"CapInh:": "0000000000000000", "CapAmb:": "0000000000000000", "NoNewPrivs:": "1",
		"Uid:": "0 0 0 0", "Gid:": "0 0 0 0", "Groups:": "",
	}
	for _, line := range strings.Split(string(status), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if expected, found := required[fields[0]]; found {
			if strings.Join(fields[1:], " ") != expected {
				return errors.New("daemon authority mismatch")
			}
			delete(required, fields[0])
		}
	}
	if len(required) != 0 {
		return errors.New("incomplete daemon authority evidence")
	}
	return nil
}
