// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"golang.org/x/sys/unix"
)

const (
	rc0BootGrantName      = "phantowd-boot"
	rc0BootControlDir     = "/run/phantowd-boot-control"
	rc0BootControlSocket  = rc0BootControlDir + "/stop"
	rc0BootServiceTimeout = 12 * time.Second
)

func manageRC0BootService(ctx context.Context, action string) error {
	if developmentBrowserEnrollment || os.Getuid() != 0 || os.Geteuid() != 0 {
		return errRC0Review
	}
	if action == "run" {
		return runRC0BootService(ctx)
	}
	if !safeRC0RunDirectory() || (action != "start" && action != "stop") {
		return errRC0Review
	}
	lock, err := lockRC0BootLifecycle()
	if err != nil {
		return err
	}
	defer lock.Close()
	switch action {
	case "start":
		return startRC0BootService(ctx)
	default:
		return stopRC0BootService(ctx)
	}
}

func lockRC0BootLifecycle() (*os.File, error) {
	fd, err := unix.Open("/run/.phantowd-boot.lock",
		unix.O_WRONLY|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	lock := os.NewFile(uintptr(fd), "rc0-boot-lifecycle-lock")
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode != unix.S_IFREG|0600 || st.Uid != 0 || st.Nlink != 1 ||
		unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB) != nil {
		return nil, errors.Join(errRC0Review, lock.Close())
	}
	return lock, nil
}

func openRC0BootGrants() ([]*os.File, error) {
	if _, err := os.Lstat("/run/" + rc0BootGrantName); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	run, err := os.Open("/run")
	if err != nil {
		return nil, err
	}
	defer run.Close()
	grantDir, err := openRC0Role(run, rc0BootGrantName, unix.O_PATH|unix.O_DIRECTORY)
	if err != nil {
		return nil, err
	}
	defer grantDir.Close()
	var st unix.Stat_t
	if unix.Fstat(int(grantDir.Fd()), &st) != nil || st.Mode != unix.S_IFDIR|0700 || st.Uid != 0 {
		return nil, errRC0Review
	}
	// Only the preselected state role may cross into the admitted ext mount.
	fd, err := unix.Openat2(int(grantDir.Fd()), "state", &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, err
	}
	state := os.NewFile(uintptr(fd), "rc0-boot-state")
	plan, err := openRC0PrivateFile(grantDir, "boot.json", rc0BootMaxBytes)
	if err != nil {
		return nil, errors.Join(err, state.Close())
	}
	policy, err := openRC0PrivateFile(grantDir, "policy.json", naspolicy.MaxInputBytes)
	if err != nil {
		return nil, errors.Join(err, state.Close(), plan.Close())
	}
	return []*os.File{state, plan, policy}, nil
}

func startRC0BootService(ctx context.Context) error {
	grants, err := openRC0BootGrants()
	if err != nil {
		return err
	}
	if grants == nil {
		fmt.Println("PhantoWD management waiting for admitted boot state")
		return nil
	}
	defer func() {
		for _, grant := range grants {
			grant.Close()
		}
	}()
	ack, childAck, err := os.Pipe()
	if err != nil {
		return err
	}
	defer ack.Close()
	defer childAck.Close()
	cmd := exec.Command("/proc/self/exe", "--rc0-boot-service=run")
	cmd.ExtraFiles = append(grants, childAck)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := ack.SetReadDeadline(time.Now().Add(rc0BootServiceTimeout)); err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	childAck.Close()
	stop := context.AfterFunc(ctx, func() { _ = ack.SetReadDeadline(time.Now()) })
	defer stop()
	var reply [1]byte
	if _, err := io.ReadFull(ack, reply[:]); err == nil && reply[0] == 'R' && ctx.Err() == nil {
		return cmd.Process.Release()
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	return errors.Join(errRC0Review, stopRC0API(cmd.Process, done))
}

func runRC0BootService(ctx context.Context) error {
	ack, err := takeStartupFile(6, unix.S_IFIFO)
	if err != nil {
		return err
	}
	defer ack.Close()
	if !safeRC0RunDirectory() {
		return errRC0Review
	}
	if err := os.Mkdir(rc0BootControlDir, 0700); err != nil {
		return err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: rc0BootControlSocket, Net: "unix"})
	if err != nil {
		return errors.Join(err, os.Remove(rc0BootControlDir))
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := make(chan *net.UnixConn, 1)
	go receiveRC0Stop(listener, cancel, stop)

	err = runRC0BootManagement(ctx, func() error {
		_, writeErr := ack.Write([]byte{'R'})
		return errors.Join(writeErr, ack.Close())
	})
	err = errors.Join(err, listener.Close(), os.Remove(rc0BootControlDir))
	if conn := <-stop; conn != nil {
		defer conn.Close()
		if err == nil {
			if deadlineErr := conn.SetWriteDeadline(time.Now().Add(time.Second)); deadlineErr != nil {
				return deadlineErr
			}
			_, err = conn.Write([]byte{'S'})
		}
	}
	return err
}

func receiveRC0Stop(listener *net.UnixListener, cancel context.CancelFunc, stop chan<- *net.UnixConn) {
	for {
		conn, err := listener.AcceptUnix()
		if err != nil {
			stop <- nil
			return
		}
		conn.SetReadDeadline(time.Now().Add(time.Second))
		var request [1]byte
		if _, err := io.ReadFull(conn, request[:]); err == nil && request[0] == 'S' {
			stop <- conn
			cancel()
			return
		}
		conn.Close()
	}
}

func stopRC0BootService(ctx context.Context) error {
	var st unix.Stat_t
	err := unix.Lstat(rc0BootControlDir, &st)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil || !safeRC0RunDirectory() || st.Mode != unix.S_IFDIR|0700 || st.Uid != 0 {
		return errRC0Review
	}
	ctx, cancel := context.WithTimeout(ctx, rc0BootServiceTimeout)
	defer cancel()
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "unix", rc0BootControlSocket)
	if err != nil {
		return err
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}
	if _, err := conn.Write([]byte{'S'}); err != nil {
		return err
	}
	var reply [1]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil || reply[0] != 'S' {
		return errRC0Review
	}
	return nil
}
