//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"golang.org/x/sys/unix"
)

const serverObserverBootstrapObjectQEMU = "usr/sbin/phantowd-server-observer-daemon-bootstrap"

// Private, single-use fixture lifecycle, not product/worker or WRITE authority.
// No caller-chosen launcher/probe, endpoint, per-call backend or descriptor is
// exposed. Mutable state retains directory identities, never TDB checksums.
type serverObserverRuntimeQEMU struct {
	self          *serverObserverRuntimeQEMU
	gate          chan struct{}
	code          *serverObserverCodeQEMU
	configuration *retainedConfiguration
	state         *retainedSambaState
	shares        [2]*os.File
	shareIdentity [2]serverObserverRootIdentityQEMU
	channel       *pendingServerPacketQEMU
	daemon        *processowner.NativeObserverDaemonQEMU
	proc          *os.File
	captureStatus *processowner.CaptureOwner
	captureWorker *serverCaptureWorkerQEMU
	pid           int
	attempted     bool
	review        bool
	closed        bool
	releaseErr    error
}

func serverObserverDocumentsQEMU() map[string]string {
	return map[string]string{
		"passwd":        "root:x:0:0:root:/:/bin/false\nnobody:x:65534:65534:nobody:/:/bin/false\n",
		"group":         "root:x:0:\nnogroup:x:65534:\n",
		"nsswitch.conf": "passwd: files\ngroup: files\n",
		"samba/smb.conf": "[global]\nserver role = standalone server\nworkgroup = QEMU\n" +
			"netbios name = OBSERVER\ninterfaces = 127.0.0.1\nbind interfaces only = yes\n" +
			"disable netbios = yes\nsmb ports = 1445\nserver min protocol = SMB3_02\nserver max protocol = SMB3_02\n" +
			"passdb backend = tdbsam:/state/private/passdb.tdb\nprivate dir = /state/private\n" +
			"lock directory = /state/lock\nstate directory = /state/state\ncache directory = /state/cache\n" +
			"pid directory = /state/pid\nncalrpc dir = /state/rpc\nload printers = no\nprinting = bsd\n" +
			"printcap name = /etc/passwd\nlog level = 0\n[readonly]\npath = /shares/readonly\nread only = yes\nguest ok = no\n",
	}
}

func newServerObserverRuntimeQEMU(ctx context.Context, plan *Plan, code, configuration, state *os.File, shares [2]*os.File) (retained *serverObserverRuntimeQEMU, result error) {
	return newServerObserverProfileRuntimeQEMU(ctx, plan, code, configuration, state, shares, serverObserverNegotiationProfileQEMU)
}

func newServerObserverProfileRuntimeQEMU(ctx context.Context, plan *Plan, code, configuration, state *os.File, shares [2]*os.File, profile serverObserverProfileQEMU) (retained *serverObserverRuntimeQEMU, result error) {
	if ctx == nil || plan == nil || code == nil || configuration == nil || state == nil || shares[0] == nil || shares[1] == nil {
		return nil, ErrInvalid
	}
	if profile != serverObserverNegotiationProfileQEMU && profile != serverObserverCaptureProfileQEMU {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := serverObserverCodeGuardQEMU(); err != nil {
		return nil, err
	}
	r := &serverObserverRuntimeQEMU{gate: make(chan struct{}, 1)}
	r.self = r
	defer func() {
		if result != nil {
			if closeErr := r.Close(); closeErr != nil {
				r.review = true
				retained = r
				result = errors.Join(ErrReviewRequired, result, closeErr)
			}
		}
	}()
	var err error
	r.code, err = retainServerObserverCodeQEMU(ctx, plan, code)
	if err != nil {
		return nil, err
	}
	helper := r.code.code.files[serverObserverBootstrapObjectQEMU]
	if helper == nil || r.code.code.files["usr/sbin/smbd"] == nil || staticExecutable(helper) != nil {
		return nil, ErrInvalid
	}
	documents := serverObserverDocumentsQEMU()
	if profile == serverObserverCaptureProfileQEMU {
		if r.code.code.files[serverCaptureModuleObjectQEMU] == nil {
			return nil, ErrInvalid
		}
		documents = serverCaptureDocumentsQEMU()
	}
	var expected []File
	for name, contents := range documents {
		mode := uint32(0644)
		if name == "samba/smb.conf" {
			mode = 0600
		}
		expected = append(expected, File{Path: name, Mode: mode, Size: int64(len(contents)), SHA256: sha256.Sum256([]byte(contents))})
	}
	configPlan, err := newConfigurationPlan(expected)
	if err != nil {
		return nil, err
	}
	r.configuration, err = configPlan.retain(ctx, configuration)
	if err != nil {
		return nil, err
	}
	r.state, err = retainSambaState(ctx, state)
	if err != nil {
		return nil, err
	}
	for i, source := range shares {
		r.shares[i], err = duplicateRoot(source)
		if err != nil {
			return nil, err
		}
		r.shareIdentity[i], err = serverObserverShareIdentityQEMU(r.shares[i], i == 0)
		if err != nil {
			return nil, err
		}
	}
	if r.shareIdentity[0].mount == r.shareIdentity[1].mount {
		return nil, ErrMismatch
	}
	r.channel, err = newPendingServerPacketQEMU(ctx)
	if err != nil {
		return nil, err
	}
	fd, err := openBeneath(int(r.configuration.contents.root.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return nil, err
	}
	configRoot := os.NewFile(uintptr(fd), "observer-config-handoff-root")
	configs := [5]*os.File{configRoot, r.configuration.contents.files["passwd"], r.configuration.contents.files["group"],
		r.configuration.contents.files["nsswitch.conf"], r.configuration.contents.files["samba/smb.conf"]}
	var states [7]*os.File
	for i, role := range sambaStateDirectories {
		states[i] = r.state.files[role]
	}
	spec := processowner.MemberSpec{Name: "native-samba-observer", Process: processowner.Spec{
		Executable: "/" + serverObserverBootstrapObjectQEMU, RunAs: &processowner.Credentials{UID: 0, GID: 0},
		ReadyTimeout: 12 * time.Second, ProbeInterval: 200 * time.Millisecond, StopTimeout: 4 * time.Second,
		Ready: func(ctx context.Context) (bool, error) {
			if err := r.checkInputs(ctx); err != nil {
				return false, err
			}
			return serverObserverNegotiateQEMU(ctx)
		},
	}}
	r.daemon, err = processowner.NewNativeObserverDaemonQEMU(spec, helper, configs, states, r.shares, r.channel.sender)
	closeErr := configRoot.Close()
	if err != nil || closeErr != nil {
		return nil, errors.Join(err, closeErr)
	}
	if err := r.checkInputs(ctx); err != nil {
		return nil, err
	}
	return r, nil
}

func serverObserverShareIdentityQEMU(root *os.File, readOnly bool) (serverObserverRootIdentityQEMU, error) {
	identity, err := serverObserverRootIdentityFromFDQEMU(int(root.Fd()))
	var fs unix.Statfs_t
	expected := int64(unix.ST_NOSUID | unix.ST_NODEV | unix.ST_NOEXEC)
	if readOnly {
		expected |= unix.ST_RDONLY
	}
	if err != nil || unix.Fstatfs(int(root.Fd()), &fs) != nil || fs.Type != unix.EXT4_SUPER_MAGIC ||
		int64(fs.Flags)&(unix.ST_NOSUID|unix.ST_NODEV|unix.ST_NOEXEC|unix.ST_RDONLY) != expected {
		return serverObserverRootIdentityQEMU{}, ErrMismatch
	}
	return identity, nil
}

func (r *serverObserverRuntimeQEMU) checkInputs(ctx context.Context) error {
	if ctx == nil || r == nil || r.code == nil || r.configuration == nil || r.state == nil || r.channel == nil || r.shares[0] == nil || r.shares[1] == nil {
		return ErrInvalid
	}
	if err := r.channel.endpoints(true); err != nil || !r.channel.queueEmpty() {
		return ErrMismatch
	}
	if err := r.code.revalidate(ctx); err != nil {
		return err
	}
	if err := r.configuration.revalidate(ctx); err != nil {
		return err
	}
	if err := r.state.revalidate(ctx); err != nil {
		return err
	}
	for i, root := range r.shares {
		identity, err := serverObserverShareIdentityQEMU(root, i == 0)
		if err != nil || identity != r.shareIdentity[i] {
			return ErrMismatch
		}
	}
	if err := r.channel.endpoints(true); err != nil || !r.channel.queueEmpty() {
		return ErrMismatch
	}
	return ctx.Err()
}

func (r *serverObserverRuntimeQEMU) enter(ctx context.Context) error {
	if ctx == nil || r == nil || r.self != r || r.gate == nil {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case r.gate <- struct{}{}:
		return nil
	default:
		return processowner.ErrBusy
	}
}

func (r *serverObserverRuntimeQEMU) contain(cause error) (processowner.SetSnapshot, error) {
	r.review = true
	observed, stopErr := r.daemon.Stop(context.Background())
	observed.State = processowner.StateReviewRequired
	return observed, errors.Join(ErrReviewRequired, cause, stopErr)
}

func (r *serverObserverRuntimeQEMU) Start(ctx context.Context) (processowner.SetSnapshot, error) {
	if err := r.enter(ctx); err != nil {
		return processowner.SetSnapshot{}, err
	}
	defer func() { <-r.gate }()
	if r.closed || r.review || r.attempted {
		return processowner.SetSnapshot{}, ErrReviewRequired
	}
	r.attempted = true
	if err := r.checkInputs(ctx); err != nil {
		return r.contain(err)
	}
	started, err := r.daemon.Start(ctx)
	if err != nil || started.State != processowner.StateReady || len(started.Members) != 1 || started.Members[0].Process.PID <= 1 {
		return r.contain(errors.Join(ErrMismatch, err))
	}
	r.pid = started.Members[0].Process.PID
	fd, err := unix.Open("/proc/"+strconv.Itoa(r.pid), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return r.contain(err)
	}
	r.proc = os.NewFile(uintptr(fd), "original-observer-daemon-proc")
	if err := r.checkProcess(); err != nil {
		return r.contain(err)
	}
	if err := r.checkInputs(ctx); err != nil {
		return r.contain(err)
	}
	observed, err := r.daemon.Observe(ctx)
	if err != nil || len(observed.Members) != 1 || observed.State != processowner.StateReady || observed.Members[0].Process.PID != r.pid {
		return r.contain(errors.Join(ErrMismatch, err))
	}
	return observed, nil
}

func (r *serverObserverRuntimeQEMU) checkProcess() error {
	if r.proc == nil || r.pid <= 1 {
		return ErrMismatch
	}
	fd, err := unix.Openat(int(r.proc.Fd()), "exe", unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return ErrMismatch
	}
	var actual, expected unix.Stat_t
	actualErr := unix.Fstat(fd, &actual)
	expectedErr := unix.Fstat(int(r.code.code.files["usr/sbin/smbd"].Fd()), &expected)
	closeErr := unix.Close(fd)
	if actualErr != nil || expectedErr != nil || closeErr != nil || actual.Dev != expected.Dev || actual.Ino != expected.Ino {
		return ErrMismatch
	}
	var link [96]byte
	n, err := unix.Readlinkat(int(r.proc.Fd()), "fd/3", link[:])
	if err != nil || string(link[:n]) != fmt.Sprintf("socket:[%d]", r.channel.right.inode) {
		return ErrMismatch
	}
	return nil
}

func (r *serverObserverRuntimeQEMU) Observe(ctx context.Context) (processowner.SetSnapshot, error) {
	if err := r.enter(ctx); err != nil {
		return processowner.SetSnapshot{}, err
	}
	defer func() { <-r.gate }()
	if r.closed || r.review {
		return processowner.SetSnapshot{}, ErrReviewRequired
	}
	if err := r.checkInputs(ctx); err != nil {
		return r.contain(err)
	}
	observed, err := r.daemon.Observe(ctx)
	if err != nil || observed.State != processowner.StateReady || len(observed.Members) != 1 || observed.Members[0].Process.PID != r.pid {
		return r.contain(errors.Join(ErrMismatch, err))
	}
	if err := r.checkProcess(); err != nil {
		return r.contain(err)
	}
	if err := r.checkInputs(ctx); err != nil {
		return r.contain(err)
	}
	return observed, nil
}

func (r *serverObserverRuntimeQEMU) Stop(ctx context.Context) (processowner.SetSnapshot, error) {
	if ctx == nil {
		return processowner.SetSnapshot{}, ErrInvalid
	}
	if err := r.enter(context.Background()); err != nil {
		return processowner.SetSnapshot{}, err
	}
	defer func() { <-r.gate }()
	if r.closed {
		return processowner.SetSnapshot{}, ErrReviewRequired
	}
	if r.daemon == nil {
		return processowner.SetSnapshot{State: processowner.StateReviewRequired}, ErrReviewRequired
	}
	if r.checkInputs(context.Background()) != nil {
		r.review = true
	}
	observed, err := r.daemon.Stop(context.Background())
	if err != nil || r.checkInputs(context.Background()) != nil {
		r.review = true
	}
	if r.review {
		observed.State = processowner.StateReviewRequired
		return observed, errors.Join(ErrReviewRequired, err)
	}
	return observed, nil
}

// Close never signals. The adapter establishes verified whole-group absence
// before any runtime input is released; every close error is terminal/sticky.
func (r *serverObserverRuntimeQEMU) Close() error {
	if err := r.enter(context.Background()); err != nil {
		return err
	}
	defer func() { <-r.gate }()
	if r.releaseErr != nil {
		return errors.Join(ErrReviewRequired, r.releaseErr)
	}
	if r.closed {
		return nil
	}
	if r.captureStatus != nil {
		settled, err := r.captureStatus.Settled(context.Background())
		if err != nil || !settled {
			r.review = true
			return errors.Join(ErrReviewRequired, err)
		}
	}
	if r.daemon != nil {
		if err := r.daemon.Close(); err != nil {
			if !errors.Is(err, processowner.ErrAlreadyRunning) && !errors.Is(err, processowner.ErrBusy) {
				r.review, r.releaseErr = true, err
			}
			return err
		}
	}
	for _, close := range []func() error{
		func() error {
			if r.captureWorker != nil && r.captureWorker.file != nil {
				return r.captureWorker.file.Close()
			}
			return nil
		},
		func() error {
			if r.captureStatus != nil {
				return r.captureStatus.Close(context.Background())
			}
			return nil
		},
		func() error {
			if r.captureWorker != nil && r.captureWorker.proc != nil {
				return r.captureWorker.proc.Close()
			}
			return nil
		},
		func() error {
			if r.proc != nil {
				return r.proc.Close()
			}
			return nil
		},
		func() error {
			if r.shares[0] != nil {
				return r.shares[0].Close()
			}
			return nil
		},
		func() error {
			if r.shares[1] != nil {
				return r.shares[1].Close()
			}
			return nil
		},
		func() error { return r.state.release() },
		func() error { return r.configuration.release() },
		func() error { return r.code.release() },
		func() error {
			if r.channel != nil {
				return r.channel.close()
			}
			return nil
		},
	} {
		if err := close(); err != nil {
			r.review, r.releaseErr = true, err
			return errors.Join(ErrReviewRequired, err)
		}
	}
	r.closed = true
	return nil
}

func serverObserverNegotiateQEMU(ctx context.Context) (bool, error) {
	dialer := net.Dialer{Timeout: 200 * time.Millisecond}
	connection, err := dialer.DialContext(ctx, "tcp", "127.0.0.1:1445")
	if err != nil {
		return false, ctx.Err()
	}
	defer connection.Close()
	deadline := time.Now().Add(2 * time.Second)
	if limit, ok := ctx.Deadline(); ok && limit.Before(deadline) {
		deadline = limit
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return false, err
	}
	var request [106]byte
	request[3] = 102
	copy(request[4:8], []byte{0xfe, 'S', 'M', 'B'})
	request[8], request[18], request[68], request[70], request[72] = 64, 1, 36, 1, 1
	copy(request[80:96], []byte("qemu-observer-01"))
	request[104], request[105] = 2, 3
	if n, err := connection.Write(request[:]); err != nil || n != len(request) {
		return false, ErrMismatch
	}
	var header [4]byte
	if _, err := io.ReadFull(connection, header[:]); err != nil {
		return false, err
	}
	length := int(header[1])<<16 | int(header[2])<<8 | int(header[3])
	if header[0] != 0 || length < 128 || length > 4096 {
		return false, ErrMismatch
	}
	response := make([]byte, length)
	if _, err := io.ReadFull(connection, response); err != nil {
		return false, err
	}
	if string(response[:4]) != "\xfeSMB" || response[4] != 64 || response[8] != 0 || response[9] != 0 ||
		response[10] != 0 || response[11] != 0 || response[12] != 0 || response[13] != 0 || response[16]&1 != 1 ||
		response[64] != 65 || response[68] != 2 || response[69] != 3 {
		return false, ErrMismatch
	}
	return true, ctx.Err()
}
