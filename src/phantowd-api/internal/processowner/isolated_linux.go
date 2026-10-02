//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Isolation is an internal trusted-construction input, not an RPC/HTTP record.
// Root must already contain exactly the authorized grants/runtime inputs. This
// package does not create that root or establish storage lease completeness.
type Isolation struct {
	LauncherExecutable string
	Root               *os.File
}

// IsolatedOwner fixes the process spec and pinned execution boundary once. No
// Start call accepts a path, credential, backend or replacement root.
type IsolatedOwner struct {
	mu     sync.Mutex
	owner  *Owner
	spec   Spec
	launch *isolatedLaunch
	closed bool
}

type isolatedLaunch struct {
	executable *os.File
	launcher   *os.File
	root       *os.File
	rootStat   unix.Stat_t
	rootMount  uint64
}

func (Isolation) MarshalJSON() ([]byte, error) {
	return nil, errors.New("service isolation is internal and not serializable")
}

func (*Isolation) UnmarshalJSON([]byte) error {
	return errors.New("service isolation cannot be deserialized")
}

// NewIsolated pins an independent copy of each descriptor and immutable spec.
// The caller remains responsible for trusted executable/root content, grants,
// storage freshness/leases and service-specific readiness. It starts nothing.
func NewIsolated(spec Spec, isolation Isolation) (*IsolatedOwner, error) {
	fixed, err := isolatedSpec(spec)
	if err != nil || isolation.Root == nil || !filepath.IsAbs(isolation.LauncherExecutable) ||
		filepath.Clean(isolation.LauncherExecutable) != isolation.LauncherExecutable ||
		strings.ContainsRune(isolation.LauncherExecutable, '\x00') {
		return nil, ErrInvalid
	}
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		return nil, ErrUnavailable
	}
	launch := &isolatedLaunch{}
	keep := false
	defer func() {
		if !keep {
			_ = launch.close()
		}
	}()
	launch.executable, err = openExecutable(fixed.Executable)
	if err != nil || trustedExecutable(launch.executable) != nil {
		return nil, ErrInvalid
	}
	launch.launcher, err = openExecutable(isolation.LauncherExecutable)
	if err != nil || trustedExecutable(launch.launcher) != nil {
		return nil, ErrInvalid
	}
	fd, err := unix.FcntlInt(isolation.Root.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, ErrInvalid
	}
	launch.root = os.NewFile(uintptr(fd), "isolated-service-root")
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	var original unix.Stat_t
	if err != nil || flags&unix.O_PATH == 0 || flags&unix.O_DIRECTORY == 0 ||
		unix.Fstat(fd, &launch.rootStat) != nil || unix.Stat("/", &original) != nil ||
		launch.rootStat.Mode&unix.S_IFMT != unix.S_IFDIR || launch.rootStat.Uid != 0 ||
		launch.rootStat.Mode&0022 != 0 ||
		(launch.rootStat.Dev == original.Dev && launch.rootStat.Ino == original.Ino) {
		return nil, ErrInvalid
	}
	launch.rootMount, err = descriptorMountID(fd)
	if err != nil {
		return nil, ErrInvalid
	}
	owner := New()
	owner.launch = launch.start
	keep = true
	return &IsolatedOwner{owner: owner, spec: fixed, launch: launch}, nil
}

func isolatedSpec(spec Spec) (Spec, error) {
	if validateSpec(spec) != nil || spec.RunAs == nil || len(spec.Args) > 63 ||
		spec.RunAs.UID < 1000 || spec.RunAs.GID < 1000 {
		return Spec{}, ErrInvalid
	}
	for _, arg := range spec.Args {
		if arg == "" {
			return Spec{}, ErrInvalid
		}
	}
	for _, group := range spec.RunAs.SupplementaryGIDs {
		if group < 1000 {
			return Spec{}, ErrInvalid
		}
	}
	fixed := spec
	fixed.Args = slices.Clone(spec.Args)
	credentials := *spec.RunAs
	credentials.SupplementaryGIDs = slices.Clone(spec.RunAs.SupplementaryGIDs)
	slices.Sort(credentials.SupplementaryGIDs)
	fixed.RunAs = &credentials
	return fixed, nil
}

func trustedExecutable(file *os.File) error {
	if file == nil {
		return ErrInvalid
	}
	var stat unix.Stat_t
	fd := int(file.Fd())
	if unix.Fstat(fd, &stat) != nil || stat.Uid != 0 || stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		stat.Mode&0111 == 0 || stat.Mode&(0022|unix.S_ISUID|unix.S_ISGID) != 0 {
		return ErrInvalid
	}
	_, err := unix.Fgetxattr(fd, "security.capability", nil)
	if !errors.Is(err, unix.ENODATA) && !errors.Is(err, unix.ENOTSUP) {
		return ErrInvalid
	}
	return nil
}

func descriptorMountID(fd int) (uint64, error) {
	var stat unix.Statx_t
	if unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_NO_AUTOMOUNT,
		unix.STATX_MNT_ID, &stat) != nil || stat.Mask&unix.STATX_MNT_ID == 0 || stat.Mnt_id == 0 {
		return 0, ErrInvalid
	}
	return stat.Mnt_id, nil
}

func (l *isolatedLaunch) revalidate() error {
	if l == nil || l.root == nil || trustedExecutable(l.executable) != nil ||
		trustedExecutable(l.launcher) != nil {
		return ErrInvalid
	}
	fd := int(l.root.Fd())
	var current unix.Stat_t
	mount, err := descriptorMountID(fd)
	if err != nil || mount != l.rootMount || unix.Fstat(fd, &current) != nil ||
		current.Dev != l.rootStat.Dev || current.Ino != l.rootStat.Ino ||
		current.Mode != l.rootStat.Mode || current.Uid != l.rootStat.Uid || current.Gid != l.rootStat.Gid {
		return ErrInvalid
	}
	return nil
}

func (l *isolatedLaunch) start(spec Spec) (*managedProcess, error) {
	if l.revalidate() != nil {
		return nil, errors.Join(ErrInvalid, ErrReviewRequired)
	}
	diagnostics := newDiagnosticRing()
	command := exec.Command("/proc/self/fd/5")
	command.Args = append([]string{"trusted-service-launcher", "v1",
		strconv.FormatUint(uint64(spec.RunAs.UID), 10),
		strconv.FormatUint(uint64(spec.RunAs.GID), 10),
		isolatedGroups(spec.RunAs.SupplementaryGIDs), "--", spec.Executable}, spec.Args...)
	command.Dir = "/"
	command.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	command.ExtraFiles = []*os.File{l.executable, l.root, l.launcher}
	// nil stdin becomes read-only /dev/null. Go creates pipes for these writers.
	command.Stdout, command.Stderr = diagnostics, diagnostics
	// The trusted root helper applies the service identity after isolation, not
	// before exec. The same child remains the Owner's process-group leader.
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.WaitDelay = time.Second
	if err := command.Start(); err != nil {
		return nil, err
	}
	process := &managedProcess{command: command, pid: command.Process.Pid,
		done: make(chan struct{}), stopTimeout: spec.StopTimeout, diagnostics: diagnostics}
	go process.wait()
	return process, nil
}

func isolatedGroups(groups []uint32) string {
	if len(groups) == 0 {
		return "-"
	}
	parts := make([]string, len(groups))
	for index, group := range groups {
		parts[index] = strconv.FormatUint(uint64(group), 10)
	}
	return strings.Join(parts, ",")
}

func (l *isolatedLaunch) close() error {
	var result error
	for _, file := range []*os.File{l.executable, l.launcher, l.root} {
		if file != nil {
			result = errors.Join(result, file.Close())
		}
	}
	return result
}

func (o *IsolatedOwner) Start(ctx context.Context) (Snapshot, error) {
	if o == nil || o.owner == nil || o.launch == nil {
		return Snapshot{}, ErrUnavailable
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return Snapshot{}, ErrUnavailable
	}
	started, err := o.owner.Start(ctx, o.spec)
	if err != nil {
		return started, err
	}
	if o.launch.revalidate() != nil {
		return o.quarantineInputs()
	}
	return started, nil
}

func (o *IsolatedOwner) Stop(ctx context.Context) (Snapshot, error) {
	if o == nil || o.owner == nil || o.launch == nil {
		return Snapshot{}, ErrUnavailable
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return Snapshot{}, ErrUnavailable
	}
	return o.owner.Stop(ctx)
}

func (o *IsolatedOwner) Observe(ctx context.Context) (Snapshot, error) {
	if o == nil || o.owner == nil || o.launch == nil {
		return Snapshot{}, ErrUnavailable
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return Snapshot{}, ErrUnavailable
	}
	observed, err := o.owner.Observe(ctx)
	if err != nil {
		return observed, err
	}
	if o.launch.revalidate() != nil {
		return o.quarantineInputs()
	}
	return observed, nil
}

// The wrapper mutex exclusively owns this private Owner. Input drift stops
// a live child once and permanently blocks restart, even after restoration.
func (o *IsolatedOwner) quarantineInputs() (Snapshot, error) {
	var stopErr error
	if o.owner.current != nil {
		_, stopErr = o.owner.Stop(context.Background())
	}
	o.owner.reviewRequired = true
	o.owner.state = StateReviewRequired
	return o.owner.snapshot(), errors.Join(ErrReviewRequired, stopErr)
}

func (o *IsolatedOwner) Diagnostics() []byte {
	if o == nil || o.owner == nil {
		return nil
	}
	return o.owner.Diagnostics()
}

// Close releases pinned inputs only when no child remains owned. It does not
// stop a child, unmount a root, release a storage lease or clear review.
func (o *IsolatedOwner) Close() error {
	if o == nil || o.owner == nil || o.launch == nil {
		return ErrUnavailable
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return nil
	}
	if o.owner.current != nil {
		return ErrAlreadyRunning
	}
	o.closed = true
	return o.launch.close()
}
