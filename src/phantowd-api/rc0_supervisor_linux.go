// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicyrpc"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicystore"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smbexec"
	"golang.org/x/sys/unix"
)

const (
	rc0RuntimeDirectory = "/run/phantowd-rc0"
	rc0PolicyChannel    = rc0RuntimeDirectory + "/channel"
	rc0Confined         = unix.RESOLVE_BENEATH | unix.RESOLVE_NO_XDEV | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS
	rc0TLSIdentity      = "management-tls.pem"
	rc0TLSStage         = ".management-tls.provisioning"
)

var errRC0Review = errors.New("RC0 management authority requires review")

// runRC0Management composes management-only roles on a state root supplied by
// a trusted parent. This entry point neither discovers nor mounts the medium.
func runRC0Management(ctx context.Context, installation, address, origin string) (result error) {
	if developmentBrowserEnrollment || os.Getuid() != 0 || os.Geteuid() != 0 {
		return errRC0Review
	}
	plan := rc0BootPlan{Installation: installation, Address: address, Origin: origin}
	if !plan.validTransport() {
		return errRC0Review
	}
	state, err := takeStartupFile(3, unix.S_IFDIR)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, state.Close()) }()
	known, proofInfo, err := readRC0PolicyGrant(4)
	if err != nil {
		return err
	}
	return superviseRC0State(ctx, plan, state, known, proofInfo, nil, nil, nil)
}

func readRC0PolicyGrant(descriptor int) ([]byte, unix.Stat_t, error) {
	proof, err := takeStartupFile(descriptor, unix.S_IFREG)
	if err != nil {
		return nil, unix.Stat_t{}, err
	}
	known, proofInfo, readErr := readPrivateStartupFile(proof, 0, naspolicy.MaxInputBytes)
	return known, proofInfo, errors.Join(readErr, proof.Close())
}

func superviseRC0State(ctx context.Context, plan rc0BootPlan, state *os.File, known []byte, proofInfo unix.Stat_t, approval *rc0StorageApproval, control *rc0BootStopAuthority, started func() error) (result error) {
	uid, gid, err := managementAPIIdentity()
	if err != nil {
		return err
	}
	stateRoot, err := lockRC0StateRoot(state)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, stateRoot.Close()) }()
	if plan.StateMountID != 0 && !plan.matchesState(stateRoot) {
		return errRC0Review
	}
	policy, err := openRC0Role(stateRoot, "nas-policy", unix.O_PATH|unix.O_DIRECTORY)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, policy.Close()) }()
	owner, err := admitRC0Policy(ctx, policy, plan.Installation, known, proofInfo)
	if owner != nil {
		defer func() { result = errors.Join(result, owner.Close()) }()
	}
	if err != nil {
		return err
	}
	server, err := naspolicyrpc.NewServer(owner, uid)
	if err != nil {
		return err
	}
	accounts, err := openRC0Role(stateRoot, "accounts", unix.O_PATH|unix.O_DIRECTORY)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, accounts.Close()) }()
	identity, err := openRC0TLSIdentity(stateRoot)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, identity.Close()) }()
	if plan.TLSLeafSHA256 != "" && !plan.matchesTLS(identity) {
		return errRC0Review
	}
	chap, err := openRC0ISCSICredentials(ctx, stateRoot)
	if err != nil {
		return err
	}
	if chap != nil {
		defer func() {
			result = errors.Join(result, chap.check(context.WithoutCancel(ctx), stateRoot), chap.close())
		}()
	}
	samba, err := openRC0SambaState(stateRoot)
	if samba != nil {
		defer func() { result = errors.Join(result, samba.check(stateRoot, rc0SambaStateRole), samba.Close()) }()
	}
	if err != nil {
		return err
	}
	var identities *identityowner.Owner
	var enrollment *runtimebundle.SambaConfiguration
	var smbBackend *smbexec.EnrollmentBackend
	if approval != nil && approval.SMB != nil {
		identities, enrollment, smbBackend, err = openRC0SambaIdentities(ctx, stateRoot, samba)
	} else {
		identities, err = openRC0ServiceIdentities(stateRoot)
	}
	if enrollment != nil {
		defer func() { result = errors.Join(result, enrollment.Close()) }()
	}
	if identities != nil {
		defer func() { result = errors.Join(result, identities.Close()) }()
	}
	if err != nil {
		return err
	}
	storage, err := admitRC0BootStorage(ctx, stateRoot, approval)
	if storage != nil {
		defer func() { result = errors.Join(result, storage.Close(context.WithoutCancel(ctx))) }()
	}
	if err != nil {
		return err
	}
	listener, err := openRC0PolicyListener(gid)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, listener.Close(), os.Remove(rc0RuntimeDirectory)) }()
	if err := ctx.Err(); err != nil {
		return err
	}
	cmd := exec.Command("/proc/self/exe")
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C",
		"PHANTOWD_STATE_FD=3", tlsIdentityFDEnv + "=4",
		listenAddressEnv + "=" + plan.Address, publicOriginEnv + "=" + plan.Origin,
		"PHANTOWD_NAS_POLICY_SOCKET=" + rc0PolicyChannel}
	if started != nil {
		cmd.Env = append(cmd.Env, rc0PrebindEnv+"=1")
	}
	cmd.ExtraFiles = []*os.File{accounts, identity}
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{}}, Pdeathsig: syscall.SIGKILL}
	ready := started
	if approval != nil && (approval.NFS != nil || approval.SMB != nil) {
		if started == nil || control == nil {
			return errRC0Review
		}
		var nfs *registeredNFS
		var smb *registeredSamba
		ready = func() error {
			var err error
			if approval.SMB != nil {
				smb, err = prepareRegisteredSamba(ctx, registeredSambaGrants{
					policy: owner, identity: identities, backend: smbBackend, storage: storage, state: samba,
					verifyState: func() error { return samba.check(stateRoot, rc0SambaStateRole) },
					endpoint:    *approval.SMB, authorize: control.authorizeSamba,
				})
				if err != nil {
					return err
				}
				if err := smb.Start(ctx); err != nil {
					return err
				}
				control.stopSamba = smb.Stop
			}
			nfs, err = startRC0NFS(ctx, control, approval, owner, identities, storage)
			if err != nil {
				return err
			}
			return started()
		}
		// The policy worker has joined before teardown. Close the NFS
		// lifetime before touching its original storage and identity claims.
		defer func() {
			if nfs != nil {
				result = errors.Join(result, nfs.Close(context.WithoutCancel(ctx)))
			}
			if smb != nil {
				result = errors.Join(result, smb.Close())
			}
		}()
	}
	return superviseRC0API(ctx, cmd, listener, server, uid, gid, ready)
}

func managementAPIIdentity() (uint32, uint32, error) {
	account, err := user.Lookup("phantowd")
	if err != nil {
		return 0, 0, errRC0Review
	}
	uid, uidErr := strconv.ParseUint(account.Uid, 10, 32)
	gid, gidErr := strconv.ParseUint(account.Gid, 10, 32)
	if uidErr != nil || gidErr != nil || uid == 0 || uid > 65534 || gid == 0 || gid > 65534 {
		return 0, 0, errRC0Review
	}
	return uint32(uid), uint32(gid), nil
}

func lockRC0StateRoot(state *os.File) (*os.File, error) {
	root, err := openRC0Role(state, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOATIME)
	if err != nil {
		return nil, err
	}
	fd := int(root.Fd())
	var st unix.Stat_t
	var fs unix.Statfs_t
	if unix.Fstat(fd, &st) != nil || st.Mode != unix.S_IFDIR|0700 || st.Uid != 0 ||
		unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.EXT4_SUPER_MAGIC || unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB) != nil {
		return nil, errors.Join(errRC0Review, root.Close())
	}
	return root, nil
}

func openRC0Role(root *os.File, name string, flags uint64) (*os.File, error) {
	fd, err := unix.Openat2(int(root.Fd()), name, &unix.OpenHow{Flags: flags | unix.O_CLOEXEC, Resolve: rc0Confined})
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), "rc0-state-role"), nil
}

func openRC0TLSIdentity(root *os.File) (*os.File, error) {
	if !rc0AbsentRole(root, rc0TLSStage) {
		return nil, errRC0Review
	}
	return openRC0PrivateFile(root, rc0TLSIdentity, maxTLSIdentityBytes)
}

func openRC0PrivateFile(root *os.File, name string, limit int64) (*os.File, error) {
	pinned, err := openRC0Role(root, name, unix.O_PATH)
	if err != nil {
		return nil, err
	}
	defer pinned.Close()
	var before, after unix.Stat_t
	var proc unix.Statfs_t
	if unix.Fstat(int(pinned.Fd()), &before) != nil || !privateStartupFileSafe(before, 0, limit) ||
		unix.Statfs("/proc/self/fd", &proc) != nil || proc.Type != unix.PROC_SUPER_MAGIC {
		return nil, errRC0Review
	}
	file, err := os.Open("/proc/self/fd/" + strconv.FormatUint(uint64(pinned.Fd()), 10))
	if err != nil {
		return nil, err
	}
	if unix.Fstat(int(file.Fd()), &after) != nil || before != after {
		return nil, errors.Join(errRC0Review, file.Close())
	}
	return file, nil
}

func independentRC0PolicyProof(policy *os.File, proof unix.Stat_t) bool {
	var current unix.Stat_t
	return unix.Fstatat(int(policy.Fd()), "nas-services.json", &current, unix.AT_SYMLINK_NOFOLLOW) == nil &&
		(current.Dev != proof.Dev || current.Ino != proof.Ino)
}

func admitRC0Policy(ctx context.Context, policy *os.File, installation string, known []byte, proof unix.Stat_t) (owner *naspolicystore.Owner, result error) {
	if !independentRC0PolicyProof(policy, proof) {
		return nil, errRC0Review
	}
	bootstrap, err := naspolicystore.OpenOwnerBootstrapFromDirectory(ctx, policy, installation)
	if bootstrap != nil {
		defer func() {
			if closeErr := bootstrap.Close(); !errors.Is(closeErr, naspolicystore.ErrClosed) {
				result = errors.Join(result, closeErr)
			}
		}()
	}
	if err != nil {
		return nil, err
	}
	if _, err := bootstrap.Observe(ctx); err != nil {
		return nil, err
	}
	return bootstrap.Confirm(ctx, known)
}

func openRC0PolicyListener(gid uint32) (listener *net.UnixListener, result error) {
	if !safeRC0RunDirectory() {
		return nil, errRC0Review
	}
	if err := os.Mkdir(rc0RuntimeDirectory, 0700); err != nil {
		return nil, err
	}
	defer func() {
		if result != nil {
			if listener != nil {
				result = errors.Join(result, listener.Close())
			}
			result = errors.Join(result, os.Remove(rc0RuntimeDirectory))
			listener = nil
		}
	}()
	if err := errors.Join(os.Chown(rc0RuntimeDirectory, 0, int(gid)), os.Chmod(rc0RuntimeDirectory, 0710)); err != nil {
		return nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: rc0PolicyChannel, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err := errors.Join(os.Chown(rc0PolicyChannel, 0, int(gid)), os.Chmod(rc0PolicyChannel, 0660)); err != nil {
		return listener, err
	}
	return listener, nil
}

func safeRC0RunDirectory() bool {
	var run unix.Stat_t
	var fs unix.Statfs_t
	return unix.Lstat("/run", &run) == nil && run.Mode == unix.S_IFDIR|0755 && run.Uid == 0 &&
		unix.Statfs("/run", &fs) == nil && fs.Type == unix.TMPFS_MAGIC
}

func superviseRC0API(ctx context.Context, cmd *exec.Cmd, listener *net.UnixListener, server *naspolicyrpc.Server, uid, gid uint32, started func() error) error {
	// Pdeathsig follows the forking thread on Linux. Keep it for this lifetime.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := cmd.Start(); err != nil {
		return err
	}
	pidFD, pidErr := unix.PidfdOpen(cmd.Process.Pid, 0)
	childDone := make(chan error, 1)
	go func() { childDone <- cmd.Wait() }()
	if pidErr != nil {
		return errors.Join(errRC0Review, stopRC0API(cmd.Process, childDone))
	}
	defer unix.Close(pidFD)
	rpcCtx, cancelRPC := context.WithCancel(context.Background())
	rpcDone := make(chan error, 1)
	go func() {
		rpcDone <- serveRC0Policy(rpcCtx, listener, server, cmd.Process.Pid, pidFD, uid, gid, started)
	}()

	var result error
	rpcFinished := false
	select {
	case <-ctx.Done():
		result = stopRC0API(cmd.Process, childDone)
	case err := <-childDone:
		result = errors.Join(errRC0Review, err)
	case err := <-rpcDone:
		rpcFinished = true
		result = errors.Join(errRC0Review, err, stopRC0API(cmd.Process, childDone))
	}
	cancelRPC()
	if !rpcFinished {
		<-rpcDone
	}
	return result
}

func serveRC0Policy(ctx context.Context, listener *net.UnixListener, server *naspolicyrpc.Server, pid, pidFD int, uid, gid uint32, started func() error) error {
	if err := listener.SetDeadline(time.Now().Add(6 * time.Second)); err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { _ = listener.SetDeadline(time.Now()) })
	defer stop()
	conn, err := listener.AcceptUnix()
	if err != nil {
		return err
	}
	if !managementAPIPeer(conn, pid, uid, gid) {
		return errors.Join(errRC0Review, conn.Close())
	}
	if n, err := unix.Poll([]unix.PollFd{{Fd: int32(pidFD), Events: unix.POLLIN}}, 0); err != nil || n != 0 {
		return errors.Join(errRC0Review, conn.Close())
	}
	if started != nil {
		if err := started(); err != nil {
			return errors.Join(err, conn.Close())
		}
	}
	return server.Serve(ctx, conn)
}

func managementAPIPeer(conn *net.UnixConn, pid int, uid, gid uint32) bool {
	raw, err := conn.SyscallConn()
	if err != nil {
		return false
	}
	match := false
	err = raw.Control(func(fd uintptr) {
		creds, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		match = err == nil && int(creds.Pid) == pid && creds.Uid == uid && creds.Gid == gid
	})
	return err == nil && match
}

func stopRC0API(process *os.Process, done <-chan error) error {
	signalErr := process.Signal(syscall.SIGTERM)
	if errors.Is(signalErr, os.ErrProcessDone) {
		signalErr = nil
	}
	deadline := time.NewTimer(6 * time.Second)
	defer deadline.Stop()
	select {
	case err := <-done:
		return errors.Join(signalErr, err)
	case <-deadline.C:
		return errors.Join(errRC0Review, signalErr, process.Kill(), <-done)
	}
}
