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

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/constructionreview"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"golang.org/x/sys/unix"
)

const (
	rc0BootGrantName      = "phantowd-boot"
	rc0BootStagingName    = ".phantowd-boot.staging"
	rc0BootControlDir     = "/run/phantowd-boot-control"
	rc0BootControlSocket  = rc0BootControlDir + "/stop"
	rc0BootServiceTimeout = 20 * time.Second
	rc0BootStopTimeout    = 45 * time.Second
	rc0StopRequest        = 'S'
	rc0DrainedStopRequest = 'D'
)

func manageRC0BootService(ctx context.Context, action string) error {
	if developmentBrowserEnrollment || os.Getuid() != 0 || os.Geteuid() != 0 {
		return errRC0Review
	}
	if action == "run" {
		return runRC0BootService(ctx)
	}
	if !safeRC0RunDirectory() {
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
	case "stop":
		return stopRC0BootService(ctx, rc0StopRequest)
	case "stop-nfs-drained":
		return stopRC0BootService(ctx, rc0DrainedStopRequest)
	case "publish":
		return publishRC0BootGrant(ctx)
	case "withdraw":
		return withdrawRC0BootGrant()
	default:
		return errRC0Review
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
	run, err := os.Open("/run")
	if err != nil {
		return nil, err
	}
	defer run.Close()
	if !rc0AbsentRole(run, rc0BootStagingName) {
		return nil, errRC0Review
	}
	grantDir, err := openRC0BootDirectory(run, rc0BootGrantName)
	if errors.Is(err, unix.ENOENT) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer grantDir.Close()
	state, err := openRC0BootState(grantDir)
	if err != nil {
		return nil, err
	}
	plan, err := openRC0PrivateFile(grantDir, "boot.json", rc0BootMaxBytes)
	if err != nil {
		return nil, errors.Join(err, state.Close())
	}
	policy, err := openRC0PrivateFile(grantDir, "policy.json", naspolicy.MaxInputBytes)
	if err != nil {
		return nil, errors.Join(err, state.Close(), plan.Close())
	}
	data, _, err := readPrivateStartupFile(plan, 0, rc0BootMaxBytes)
	if err != nil {
		return nil, errors.Join(err, state.Close(), plan.Close(), policy.Close())
	}
	boot, err := decodeRC0BootPlan(data)
	if err != nil || !fixedRC0BootInventory(grantDir, boot.StorageSHA256 != "") {
		return nil, errors.Join(errRC0Review, state.Close(), plan.Close(), policy.Close())
	}
	grants := []*os.File{state, plan, policy}
	if boot.StorageSHA256 != "" {
		storage, err := openRC0PrivateFile(grantDir, rc0StorageRole, rc0StorageApprovalLimit)
		if err != nil {
			return nil, errors.Join(err, state.Close(), plan.Close(), policy.Close())
		}
		grants = append(grants, storage)
	}
	return grants, nil
}

func openRC0BootDirectory(run *os.File, name string) (*os.File, error) {
	dir, err := openRC0Role(run, name, unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return nil, err
	}
	var st unix.Stat_t
	if unix.Fstat(int(dir.Fd()), &st) != nil || st.Mode != unix.S_IFDIR|0700 || st.Uid != 0 {
		return nil, errors.Join(errRC0Review, dir.Close())
	}
	return dir, nil
}

func openRC0BootState(grant *os.File) (*os.File, error) {
	// Only the fixed state role may cross into the admitted ext mount.
	fd, err := unix.Openat2(int(grant.Fd()), "state", &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), "rc0-boot-state"), nil
}

func startRC0BootService(ctx context.Context) error {
	if !rc0BootServiceAbsent() {
		return errRC0Review
	}
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
	cmd.ExtraFiles = append(grants[:3:3], childAck)
	cmd.ExtraFiles = append(cmd.ExtraFiles, grants[3:]...)
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
	control := &rc0BootStopAuthority{}
	go receiveRC0Stop(ctx, listener, control, cancel, stop)

	admitted := false
	err = runRC0BootManagement(ctx, control, func() error {
		admitted = true
		control.ready.Store(true)
		_, writeErr := ack.Write([]byte{'R'})
		return errors.Join(writeErr, ack.Close())
	})
	cancel()
	err = errors.Join(err, listener.Close())
	conn := <-stop
	if conn != nil {
		defer conn.Close()
	}
	// The policy worker has joined before runRC0BootManagement returns. Once
	// it admitted the API, preserve the already-reserved control directory
	// unless an explicit stop completed successfully. A killed supervisor
	// also leaves the directory behind.
	if constructionreview.Contains(err) || (admitted || control.nfs.Load() || control.stopSamba != nil) && (err != nil || conn == nil) {
		return errors.Join(errRC0Review, err)
	}
	if err := errors.Join(err, os.Remove(rc0BootControlDir)); err != nil || conn == nil {
		return err
	}
	if err := conn.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		return err
	}
	_, err = conn.Write([]byte{'S'})
	return err
}

func receiveRC0Stop(ctx context.Context, listener *net.UnixListener, control *rc0BootStopAuthority, cancel context.CancelFunc, stop chan<- *net.UnixConn) {
	for {
		conn, err := listener.AcceptUnix()
		if err != nil {
			stop <- nil
			return
		}
		if receiveRC0StopRequest(conn, control) {
			drainCtx, done := context.WithTimeout(ctx, rc0BootStopTimeout-time.Second)
			err := control.drainSamba(drainCtx)
			done()
			if err != nil {
				if conn.SetWriteDeadline(time.Now().Add(time.Second)) == nil {
					_, _ = conn.Write([]byte{'B'})
				}
				conn.Close()
				continue
			}
			stop <- conn
			cancel()
			return
		}
		conn.Close()
	}
}

func receiveRC0StopRequest(conn *net.UnixConn, control *rc0BootStopAuthority) bool {
	raw, err := conn.SyscallConn()
	if err != nil {
		return false
	}
	root := false
	err = raw.Control(func(fd uintptr) {
		peer, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		root = err == nil && peer.Uid == 0 && peer.Pid > 0
	})
	if err != nil || !root || conn.SetReadDeadline(time.Now().Add(time.Second)) != nil {
		return false
	}
	var request [1]byte
	_, err = io.ReadFull(conn, request[:])
	return err == nil && control.accept(request[0])
}

func stopRC0BootService(ctx context.Context, request byte) error {
	var st unix.Stat_t
	err := unix.Lstat(rc0BootControlDir, &st)
	if errors.Is(err, unix.ENOENT) {
		if request == rc0StopRequest {
			return nil
		}
		return errRC0Review
	}
	if err != nil || !safeRC0RunDirectory() || st.Mode != unix.S_IFDIR|0700 || st.Uid != 0 {
		return errRC0Review
	}
	ctx, cancel := context.WithTimeout(ctx, rc0BootStopTimeout)
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
	if _, err := conn.Write([]byte{request}); err != nil {
		return err
	}
	var reply [1]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return errRC0Review
	}
	if reply[0] == 'B' {
		return errRC0DrainPending
	}
	if reply[0] != 'S' {
		return errRC0Review
	}
	return nil
}
