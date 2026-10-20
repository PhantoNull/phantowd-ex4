//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"slices"
	"strings"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"golang.org/x/sys/unix"
)

const nfsCodeViewQEMU = "/run/phantowd-nfs-code-view"

// NFSCodeQEMU retains code references only, not processes or execution rights.
// The containing trusted owner must retain the ORIGINAL handle/error while
// consumers or uncertainty remain. There is no descriptor getter or restart.
type NFSCodeQEMU struct{ inner *nfsCodeLifetimeQEMU }

type nfsCodeLifetimeQEMU struct {
	original  *NFSCodeQEMU
	gate      chan struct{}
	code      *retainedCode
	namespace *os.File
	ns        unix.Stat_t
	review    bool
	closed    bool
	cause     error
	// One containing source/runtime lease, never a descriptor or launch getter.
	sourceReserved bool
	sourceAccess   *NFSSourceAccessQEMU
	// Present together only for the separate complete input constructor.
	configuration *retainedConfiguration
	state         *retainedNFSStateQEMU
}

// NewNFSCodeQEMU admits only the explicit ARMv5 disposable code fixture, its
// fixed named read-only tmpfs view and independently supplied build metadata.
// It starts no child. Uncertain rollback returns a retaining construction error;
// the caller must keep that ORIGINAL error, not only its text/sentinel.
func NewNFSCodeQEMU(ctx context.Context, expected []byte, root *os.File) (_ *NFSCodeQEMU, result error) {
	if ctx == nil || root == nil {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	plan, err := NFSExpectedPlanQEMU(expected)
	if err != nil || nfsCodeGuardQEMU() != nil {
		return nil, ErrInvalid
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	o := &NFSCodeQEMU{}
	s := &nfsCodeLifetimeQEMU{original: o, gate: make(chan struct{}, 1)}
	o.inner = s
	defer func() {
		if result != nil {
			result = constructionRollback(result, s, s.releaseUnstarted)
		}
	}()
	fd, err := unix.Open("/proc/thread-self/ns/mnt", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnavailable
	}
	s.namespace = os.NewFile(uintptr(fd), "nfs-code-original-mount-namespace")
	var fs unix.Statfs_t
	kind, kindErr := unix.IoctlRetInt(fd, unix.NS_GET_NSTYPE)
	if kindErr != nil || kind != unix.CLONE_NEWNS || unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.NSFS_MAGIC ||
		unix.Fstat(fd, &s.ns) != nil || s.ns.Ino == 0 {
		return nil, ErrMismatch
	}
	s.code, err = plan.prepareRetainedCode(ctx, root)
	if err != nil {
		return nil, err
	}
	if err := s.binding(ctx); err != nil {
		return nil, err
	}
	if err := s.elfHeaders(); err != nil {
		return nil, err
	}
	if err := s.revalidate(ctx); err != nil {
		return nil, err
	}
	return o, nil
}

func nfsCodeGuardQEMU() error {
	if runtime.GOARCH != "arm" || os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 {
		return ErrInvalid
	}
	model, err := os.ReadFile("/sys/firmware/devicetree/base/model")
	if err != nil || string(model) != "ARM Versatile PB\x00" {
		return ErrInvalid
	}
	command, err := os.ReadFile("/proc/cmdline")
	if err != nil || len(command) > 4096 {
		return ErrInvalid
	}
	count := 0
	for _, word := range strings.Fields(string(command)) {
		if word == "phantowd_nfs_code_fixture=1" {
			count++
		}
	}
	if count != 1 {
		return ErrInvalid
	}
	return nil
}

func (s *nfsCodeLifetimeQEMU) binding(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.code == nil || s.code.root == nil || s.namespace == nil {
		return ErrMismatch
	}
	var held, current unix.Stat_t
	if unix.Fstat(int(s.namespace.Fd()), &held) != nil || unix.Stat("/proc/thread-self/ns/mnt", &current) != nil ||
		held.Dev != s.ns.Dev || held.Ino != s.ns.Ino || current.Dev != held.Dev || current.Ino != held.Ino {
		return ErrMismatch
	}
	var fs unix.Statfs_t
	const flags = unix.ST_RDONLY | unix.ST_NOSUID | unix.ST_NODEV
	if unix.Fstatfs(int(s.code.root.Fd()), &fs) != nil || fs.Type != unix.TMPFS_MAGIC ||
		fs.Flags&flags != flags || fs.Flags&unix.ST_NOEXEC != 0 {
		return ErrMismatch
	}
	var path unix.Statx_t
	const mask = unix.STATX_BASIC_STATS | unix.STATX_MNT_ID_UNIQUE
	original := s.code.metadata["."]
	if unix.Statx(unix.AT_FDCWD, nfsCodeViewQEMU, unix.AT_NO_AUTOMOUNT|unix.AT_SYMLINK_NOFOLLOW, mask, &path) != nil ||
		path.Mask&mask != mask || path.Mnt_id != original.Mnt_id || path.Ino != original.Ino ||
		path.Dev_major != original.Dev_major || path.Dev_minor != original.Dev_minor || path.Mode&unix.S_IFMT != unix.S_IFDIR {
		return ErrMismatch
	}
	return ctx.Err()
}

// These actual-file header/interpreter prerequisites are NOT loader, symbol,
// instruction-set, NSS/dlopen, process or full ABI qualification.
func (s *nfsCodeLifetimeQEMU) elfHeaders() error {
	programs := map[string]bool{}
	for _, name := range []string{"usr/sbin/rpcbind", "usr/sbin/rpc.mountd", "usr/sbin/exportfs"} {
		for _, alias := range s.code.plan.aliases {
			if alias.Path == name {
				name = alias.Target
				break
			}
		}
		programs[name] = true
	}
	for name, file := range s.code.files {
		var header [52]byte
		if _, err := file.ReadAt(header[:], 0); err != nil {
			return ErrMismatch
		}
		flags := binary.LittleEndian.Uint32(header[36:40])
		object, err := elf.NewFile(file)
		if err != nil || object.Class != elf.ELFCLASS32 || object.Data != elf.ELFDATA2LSB || object.Machine != elf.EM_ARM ||
			!slices.Contains([]elf.Type{elf.ET_EXEC, elf.ET_DYN}, object.Type) ||
			flags&0xff000000 != 0x05000000 || flags&0x00000400 != 0 || flags&0x00800000 != 0 {
			return ErrMismatch
		}
		interpreter, dynamic := 0, false
		for _, segment := range object.Progs {
			dynamic = dynamic || segment.Type == elf.PT_DYNAMIC
			if segment.Type != elf.PT_INTERP {
				continue
			}
			interpreter++
			if segment.Filesz > 128 {
				return ErrMismatch
			}
			value, err := io.ReadAll(io.LimitReader(segment.Open(), 129))
			if err != nil || !bytes.Equal(value, []byte("/lib/ld-linux.so.3\x00")) {
				return ErrMismatch
			}
		}
		if interpreter > 1 || programs[name] && (interpreter != 1 || !dynamic) {
			return ErrMismatch
		}
	}
	return nil
}

func (s *nfsCodeLifetimeQEMU) revalidate(ctx context.Context) error {
	if err := s.revalidateReferences(ctx); err != nil {
		return err
	}
	if s.sourceAccess != nil {
		if err := s.sourceAccess.check(ctx); err != nil {
			return err
		}
	}
	return s.binding(ctx)
}

// Original code/config/state references only. Shutdown must not re-admit a
// failed source binding. Ordinary admission always adds sourceAccess.check.
func (s *nfsCodeLifetimeQEMU) revalidateReferences(ctx context.Context) error {
	if err := s.binding(ctx); err != nil {
		return err
	}
	if err := s.code.revalidate(ctx); err != nil {
		return err
	}
	if s.configuration != nil || s.state != nil {
		if s.configuration == nil || s.state == nil {
			return ErrMismatch
		}
		if err := s.configuration.revalidate(ctx); err != nil {
			return err
		}
		if err := s.state.revalidate(ctx); err != nil {
			return err
		}
		configuration := s.configuration.contents.metadata["."]
		if err := nfsInputNamedRootQEMU(nfsConfigViewQEMU, configuration.Ino, configuration.Mnt_id, configuration.Dev_major, configuration.Dev_minor); err != nil {
			return err
		}
		state := s.state.identity["."]
		if err := nfsInputNamedRootQEMU(nfsStateViewQEMU, state.inode, state.mount, state.major, state.minor); err != nil {
			return err
		}
	}
	return s.binding(ctx)
}

func (o *NFSCodeQEMU) Check(ctx context.Context) error {
	s, err := o.enter(ctx)
	if err != nil {
		return err
	}
	defer s.leave()
	if s.review {
		return ErrReviewRequired
	}
	if s.closed {
		return ErrUnavailable
	}
	if err := s.revalidate(ctx); err != nil {
		s.review, s.cause = true, err
		if errors.Is(err, context.Canceled) {
			return errors.Join(ErrReviewRequired, context.Canceled)
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return errors.Join(ErrReviewRequired, context.DeadlineExceeded)
		}
		return ErrReviewRequired
	}
	return nil
}

// Close is explicit release after the containing consumer's verified absence.
// No process exists in this leaf. Review/uncertain close retains references and
// cannot be erased by source restoration or another call. Never retry Close.
func (o *NFSCodeQEMU) Close() error {
	s, err := o.enter(context.Background())
	if err != nil {
		return err
	}
	defer s.leave()
	if s.sourceReserved {
		return processowner.ErrBusy
	}
	if s.review {
		return ErrReviewRequired
	}
	if s.closed {
		return nil
	}
	if err := s.revalidate(context.Background()); err != nil {
		s.review, s.cause = true, err
		return ErrReviewRequired
	}
	if err := s.releaseUnstarted(); err != nil {
		s.review, s.cause = true, err
		return ErrReviewRequired
	}
	s.closed = true
	return nil
}

// Constructor-only no-child rollback, also used by verified normal closure.
func (s *nfsCodeLifetimeQEMU) releaseUnstarted() error {
	if err := s.state.release(); err != nil {
		return err
	}
	if err := s.configuration.release(); err != nil {
		return err
	}
	if s.code != nil {
		if err := s.code.release(); err != nil {
			return err
		}
	}
	if s.namespace != nil {
		err := s.namespace.Close()
		if err != nil {
			return err
		}
		s.namespace = nil
	}
	return nil
}

func (o *NFSCodeQEMU) enter(ctx context.Context) (*nfsCodeLifetimeQEMU, error) {
	if o == nil || o.inner == nil || o.inner.original != o || ctx == nil {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s := o.inner
	select {
	case s.gate <- struct{}{}:
		runtime.LockOSThread()
		return s, nil
	default:
		return nil, processowner.ErrBusy
	}
}
func (s *nfsCodeLifetimeQEMU) leave()              { runtime.UnlockOSThread(); <-s.gate }
func (NFSCodeQEMU) MarshalJSON() ([]byte, error)   { return nil, ErrInvalid }
func (*NFSCodeQEMU) UnmarshalJSON([]byte) error    { return ErrInvalid }
func (NFSCodeQEMU) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, "nfs-code{private}") }
