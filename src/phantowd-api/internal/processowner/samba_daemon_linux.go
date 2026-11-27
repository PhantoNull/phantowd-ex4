// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
	"golang.org/x/sys/unix"
)

// SambaDaemon owns one fixed isolated Samba process group. It retains the
// original launch inputs until the group has been reaped. Its caller controls
// firewall admission, protocol-level drain and identity/storage authority.
type SambaDaemon struct {
	mu        sync.Mutex
	self      *SambaDaemon
	owner     *Owner
	address   netip.Addr
	files     []*os.File
	quiescent func(context.Context) error
	listener  uint64
	attempted bool
	closed    bool
	review    bool
	closeErr  error
}

// NewSambaDaemon pins the read-only image API and the fixed child inputs. The
// child independently checks the sealed declaration, its mounts and Samba code
// before exec. Each share descriptor is in the order of the sealed declaration.
func NewSambaDaemon(address netip.Addr, declaration, configuration, private, state *os.File,
	shares []*os.File, quiescent func(context.Context) error) (_ *SambaDaemon, result error) {
	if !address.Is4() || !address.IsGlobalUnicast() || quiescent == nil ||
		len(shares) == 0 || len(shares) > shareconfig.MaxShares || os.Getuid() != 0 || os.Geteuid() != 0 {
		return nil, ErrInvalid
	}
	d := &SambaDaemon{owner: New(), address: address, quiescent: quiescent}
	d.self = d
	defer func() {
		if result != nil {
			result = errors.Join(result, d.Close())
		}
	}()
	for _, file := range append([]*os.File{declaration, configuration, private, state}, shares...) {
		if file == nil {
			return nil, ErrInvalid
		}
		fd, err := unix.FcntlInt(file.Fd(), unix.F_DUPFD_CLOEXEC, 0)
		if err != nil {
			return nil, err
		}
		d.files = append(d.files, os.NewFile(uintptr(fd), "samba-daemon-input"))
	}
	var format unix.Stat_t
	var fs unix.Statfs_t
	seals, err := unix.FcntlInt(d.files[0].Fd(), unix.F_GET_SEALS, 0)
	const required = unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	if err != nil || seals&required != required || unix.Fstat(int(d.files[0].Fd()), &format) != nil ||
		format.Mode != unix.S_IFREG|0400 || format.Uid != 0 || format.Gid != 0 || format.Size <= 0 || format.Size > 16<<10 ||
		unix.Fstatfs(int(d.files[0].Fd()), &fs) != nil || fs.Type != unix.TMPFS_MAGIC {
		return nil, ErrInvalid
	}
	const imageAPI = "/usr/bin/phantowd-api"
	program, err := openExecutable(imageAPI)
	if err != nil {
		return nil, err
	}
	d.files = append(d.files, program)
	if trustedExecutable(program) != nil || unix.Fstatfs(int(program.Fd()), &fs) != nil || fs.Flags&unix.ST_RDONLY == 0 {
		return nil, ErrInvalid
	}
	d.owner.launch = func(spec Spec) (*managedProcess, error) {
		// Linux ties parent-death signaling to the thread that forks. Keep it
		// alive until the child has been reaped, independently of Start's caller.
		type launchResult struct {
			process *managedProcess
			err     error
		}
		started := make(chan launchResult)
		go func() {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			process, err := startDescriptorProcess(spec, 3+len(d.files)-1, d.files, syscall.SIGKILL)
			started <- launchResult{process, err}
			if process != nil {
				<-process.done
			}
		}()
		result := <-started
		return result.process, result.err
	}
	return d, nil
}

func (d *SambaDaemon) Start(ctx context.Context) (Snapshot, error) {
	if d == nil || d.self != d || ctx == nil {
		return Snapshot{}, ErrInvalid
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || d.review || d.attempted || ctx.Err() != nil {
		return Snapshot{}, ErrUnavailable
	}
	if _, drained, err := observeSambaTransport(ctx, 0, d.address); err != nil || !drained {
		return Snapshot{}, errors.Join(ErrBusy, err)
	}
	d.attempted = true
	return d.owner.Start(ctx, Spec{
		Executable: "/usr/bin/phantowd-api", Args: []string{"--run-rc0-samba-child"}, RunAs: &Credentials{},
		ReadyTimeout: 15 * time.Second, ProbeInterval: 100 * time.Millisecond, StopTimeout: 5 * time.Second,
		Ready: func(ctx context.Context) (bool, error) {
			pid := d.owner.current.pid
			listener, _, err := observeSambaTransport(ctx, pid, d.address)
			if errors.Is(err, ErrBusy) {
				// The child can open its listener between the FD and socket scans.
				// Retry within the normal bounded readiness window.
				return false, nil
			}
			if err != nil {
				return false, err
			}
			d.listener = listener
			return listener != 0, nil
		},
	})
}

func (d *SambaDaemon) Observe(ctx context.Context) (Snapshot, error) {
	if d == nil || d.self != d || ctx == nil {
		return Snapshot{}, ErrInvalid
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || d.review {
		return Snapshot{}, ErrReviewRequired
	}
	state, err := d.owner.Observe(ctx)
	if err == nil && state.State == StateReady {
		_, err = d.checkTransport(ctx, state.PID)
		if d.review {
			state.State = StateReviewRequired
		}
	}
	return state, err
}

func (d *SambaDaemon) checkTransport(ctx context.Context, pid int) (bool, error) {
	listener, drained, err := observeSambaTransport(ctx, pid, d.address)
	if err != nil || listener == 0 || listener != d.listener {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		d.review = true
		return false, ErrReviewRequired
	}
	return drained, nil
}

// Stop permits graceful group shutdown only after the caller has fenced new
// connections and confirmed protocol quiescence. Live TCP connections refuse
// the request even after that confirmation. A refused stop sends no signal.
func (d *SambaDaemon) Stop(ctx context.Context) (Snapshot, error) {
	if d == nil || d.self != d || ctx == nil || ctx.Err() != nil {
		return Snapshot{}, ErrInvalid
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || d.review {
		return Snapshot{}, ErrReviewRequired
	}
	observed, err := d.owner.Observe(ctx)
	if err == nil && d.attempted && observed.State == StateStopped {
		return observed, nil
	}
	if err != nil || observed.State != StateReady {
		return observed, errors.Join(ErrUnavailable, err)
	}
	if err := d.quiescent(ctx); err != nil {
		return observed, err
	}
	drained, err := d.checkTransport(ctx, observed.PID)
	if err != nil {
		if d.review {
			observed.State = StateReviewRequired
		}
		return observed, err
	}
	if !drained {
		return observed, ErrBusy
	}
	state, err := d.owner.Stop(ctx)
	if err != nil {
		d.review = true
	}
	return state, err
}

// Abort settles the original group after a supervisor failure. It always
// requires review and cannot be reported as a protocol-confirmed shutdown.
func (d *SambaDaemon) Abort() error {
	if d == nil || d.self != d {
		return ErrInvalid
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return ErrUnavailable
	}
	d.review = true
	_, err := d.owner.Stop(context.Background())
	return errors.Join(ErrReviewRequired, err)
}

func (d *SambaDaemon) Close() error {
	if d == nil || d.self != d {
		return ErrInvalid
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.owner.current != nil {
		return ErrAlreadyRunning
	}
	if d.closed {
		return d.closeErr
	}
	d.closed = true
	for _, file := range d.files {
		if err := file.Close(); err != nil {
			d.closeErr = errors.Join(ErrReviewRequired, err)
			return d.closeErr
		}
	}
	d.files = nil
	return nil
}
