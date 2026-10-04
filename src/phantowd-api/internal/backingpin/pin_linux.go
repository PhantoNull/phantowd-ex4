//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package backingpin retains metadata-only references to an existing file
// under a caller-owned qualified mountguard. It is not writable authority,
// allocation/ownership admission or a target backend. The mounted constructor
// can retain, but cannot create or qualify, an existing complete roster lease.
package backingpin

import (
	"errors"
	"io/fs"
	"math"
	"os"
	"path"
	"strings"
	"sync"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/mountguard"
	"golang.org/x/sys/unix"
)

var (
	ErrInvalid     = errors.New("invalid backing metadata selection")
	ErrUnavailable = errors.New("backing metadata unavailable")
	ErrReview      = errors.New("backing metadata requires review")
	ErrClosed      = errors.New("backing metadata pin closed")
	ErrBusy        = errors.New("backing references owned by a consumer")
)

// Observation is deliberately nonserializable. AllocatedBytes observes statx
// sectors only, not extent coverage, reservation, quotas or available space.
type Observation struct {
	sizeBytes, allocatedBytes uint64
	readOnly                  bool
}

func (o Observation) SizeBytes() uint64          { return o.sizeBytes }
func (o Observation) AllocatedBytes() uint64     { return o.allocatedBytes }
func (o Observation) FilesystemReadOnly() bool   { return o.readOnly }
func (Observation) MarshalJSON() ([]byte, error) { return nil, ErrUnavailable }
func (*Observation) UnmarshalJSON([]byte) error  { return ErrUnavailable }

type rootGuard interface {
	Verify() error
	OpenDirectory(string) (*os.File, error)
}

// Promoted value methods refuse serialization even for a mistakenly copied
// Pin value, without copying the mutex in a value-receiver MarshalJSON.
type nonSerializable struct{}

func (nonSerializable) MarshalJSON() ([]byte, error) { return nil, ErrUnavailable }
func (*nonSerializable) UnmarshalJSON([]byte) error  { return ErrUnavailable }

type identity struct {
	mount, inode             uint64
	major, minor, filesystem uint32
	mode                     uint16
	uid, gid, links          uint32
	size                     uint64
	readOnly                 bool
}

// Pin must not be copied. It owns parent/leaf O_PATH references; Open borrows
// Root, while OpenFromMountedLease owns a private retained roster-root pin. No FD,
// path, inode, device tuple or backend handoff escapes this package.
type Pin struct {
	nonSerializable
	mu                           sync.Mutex
	root                         rootGuard
	parent, file                 *os.File
	directory, name              string
	parentIdentity, fileIdentity identity
	review, closed               bool
	closeError                   error
	consumer                     *writableOwner
	mountRoot                    *mountowner.VolumeRootPin
	volumeID                     string // immutable mounted-member selection, not registry authority
}

// Open pins an existing regular, single-link file of the exact expected size.
// Neither a desired policy nor registry/census diagnostics mint this Root.
// A production lifecycle qualifier is still required; currently only fixtures
// call this constructor. No create, truncate, data read/write or weak retry.
func Open(root *mountguard.Root, relative string, expectedSize uint64) (*Pin, Observation, error) {
	if root == nil {
		return nil, Observation{}, ErrInvalid
	}
	return openWith(root, relative, expectedSize)
}

// OpenFromMountedLease retains the complete existing mount-owner roster lease
// while resolving one backing member. The root pin never escapes to callers;
// direct group Close stays busy until safe metadata/consumer release. This
// acquires no data descriptor or access/allocation/global-use/session authority.
func OpenFromMountedLease(lease *mountowner.MountedVolumeSetLease, volumeID, relative string, expectedSize uint64) (*Pin, Observation, error) {
	if lease == nil || !validSelection(relative, expectedSize) {
		return nil, Observation{}, ErrInvalid
	}
	root, err := lease.PinVolumeRoot(volumeID)
	if err != nil {
		return nil, Observation{}, ErrUnavailable
	}
	pin, observation, err := openWith(root, relative, expectedSize)
	if err != nil {
		// Uncertain metadata close cannot release the retained mount lifetime.
		// The group keeps the opaque pin for review; no implicit recovery/retry.
		if !errors.Is(err, ErrReview) && root.Release() != nil {
			err = ErrReview
		}
		return nil, Observation{}, err
	}
	pin.mountRoot = root
	pin.volumeID = volumeID
	return pin, observation, nil
}

func validSelection(relative string, expectedSize uint64) bool {
	return fs.ValidPath(relative) && relative != "." && len(relative) <= 1024 &&
		!strings.ContainsAny(relative, "\\\x00") && expectedSize >= 512 && expectedSize <= math.MaxInt64 && expectedSize%512 == 0
}

// Private construction seam for native lifecycle tests, never request input.
func openWith(root rootGuard, relative string, expectedSize uint64) (*Pin, Observation, error) {
	if root == nil || !validSelection(relative, expectedSize) {
		return nil, Observation{}, ErrInvalid
	}
	p := &Pin{root: root, directory: path.Dir(relative), name: path.Base(relative)}
	parent, err := root.OpenDirectory(p.directory)
	if err != nil || parent == nil {
		if parent != nil {
			if parent.Close() != nil {
				return nil, Observation{}, ErrReview
			}
		}
		return nil, Observation{}, ErrUnavailable
	}
	p.parent = parent
	fail := func() (*Pin, Observation, error) {
		if p.closeLocked() != nil {
			return nil, Observation{}, ErrReview
		}
		return nil, Observation{}, ErrUnavailable
	}
	p.parentIdentity, _, err = observe(parent, false)
	if err != nil {
		return fail()
	}
	p.file, err = openLeaf(parent, p.name)
	if err != nil {
		return fail()
	}
	p.fileIdentity, _, err = observe(p.file, true)
	if err != nil || !sameMount(p.parentIdentity, p.fileIdentity) || p.fileIdentity.size != expectedSize {
		return fail()
	}
	observation, err := p.verifyLocked()
	if err != nil {
		return fail()
	}
	return p, observation, nil
}

// Verify compares retained and independently re-resolved objects. Any observed
// uncertainty permanently quarantines this Pin but keeps its references until
// explicit Close. Restoring a pathname never rehabilitates a reviewed pin.
// This is a point-in-time check, not a global-use lock or change-history proof.
func (p *Pin) Verify() (Observation, error) {
	if p == nil {
		return Observation{}, ErrClosed
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.verifyLocked()
}

func (p *Pin) verifyLocked() (Observation, error) {
	if p.closed || p.root == nil || p.parent == nil || p.file == nil {
		return Observation{}, ErrClosed
	}
	if p.review {
		return Observation{}, ErrReview
	}
	fail := func() (Observation, error) { p.review = true; return Observation{}, ErrReview }
	if p.root.Verify() != nil {
		return fail()
	}
	parent, err := p.root.OpenDirectory(p.directory)
	if err != nil || parent == nil {
		if parent != nil {
			_ = parent.Close()
		}
		return fail()
	}
	parentID, _, err := observe(parent, false)
	if err != nil || parentID != p.parentIdentity {
		_ = parent.Close()
		return fail()
	}
	named, err := openLeaf(parent, p.name)
	if parent.Close() != nil {
		if named != nil {
			_ = named.Close()
		}
		return fail()
	}
	if err != nil || named == nil {
		return fail()
	}
	namedID, _, err := observe(named, true)
	if named.Close() != nil || err != nil || namedID != p.fileIdentity {
		return fail()
	}
	parentID, _, err = observe(p.parent, false)
	if err != nil || parentID != p.parentIdentity {
		return fail()
	}
	fileID, observation, err := observe(p.file, true)
	if err != nil || fileID != p.fileIdentity || p.root.Verify() != nil {
		return fail()
	}
	return observation, nil
}

func (p *Pin) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.consumer != nil {
		return ErrBusy
	}
	return p.closeLocked()
}

func (p *Pin) closeLocked() error {
	if p.closed {
		return p.closeError
	}
	p.closed = true
	var result error
	for _, file := range []*os.File{p.file, p.parent} {
		if file != nil && file.Close() != nil {
			result = ErrReview
			p.review = true
		}
	}
	p.file, p.parent, p.root = nil, nil, nil
	if result == nil && p.mountRoot != nil {
		if p.mountRoot.Release() != nil {
			result = ErrReview
			p.review = true
		} else {
			p.mountRoot = nil
		}
	}
	p.closeError = result
	return result
}

func openLeaf(parent *os.File, name string) (*os.File, error) {
	fd, err := unix.Openat2(int(parent.Fd()), name, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV})
	if err != nil {
		return nil, ErrUnavailable
	}
	return os.NewFile(uintptr(fd), "backing-metadata"), nil
}

func observe(file *os.File, regular bool) (identity, Observation, error) {
	var st unix.Statx_t
	var filesystem unix.Statfs_t
	if unix.Statx(int(file.Fd()), "", unix.AT_EMPTY_PATH|unix.AT_NO_AUTOMOUNT,
		unix.STATX_BASIC_STATS|unix.STATX_MNT_ID_UNIQUE, &st) != nil || unix.Fstatfs(int(file.Fd()), &filesystem) != nil {
		return identity{}, Observation{}, ErrUnavailable
	}
	return observed(st, filesystem, regular)
}

func observed(st unix.Statx_t, filesystem unix.Statfs_t, regular bool) (identity, Observation, error) {
	const required = unix.STATX_TYPE | unix.STATX_INO | unix.STATX_MNT_ID_UNIQUE
	if st.Mask&required != required || st.Mnt_id == 0 || st.Ino == 0 {
		return identity{}, Observation{}, ErrUnavailable
	}
	id := identity{mount: st.Mnt_id, inode: st.Ino, major: st.Dev_major, minor: st.Dev_minor,
		filesystem: uint32(filesystem.Type), readOnly: filesystem.Flags&unix.ST_RDONLY != 0}
	if !regular {
		if st.Mode&unix.S_IFMT != unix.S_IFDIR {
			return identity{}, Observation{}, ErrUnavailable
		}
		return id, Observation{}, nil
	}
	const fileRequired = required | unix.STATX_MODE | unix.STATX_NLINK | unix.STATX_UID | unix.STATX_GID | unix.STATX_SIZE | unix.STATX_BLOCKS
	if st.Mask&fileRequired != fileRequired || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 ||
		st.Size > math.MaxInt64 || st.Blocks > math.MaxInt64/512 {
		return identity{}, Observation{}, ErrUnavailable
	}
	id.mode, id.uid, id.gid, id.links, id.size = st.Mode, st.Uid, st.Gid, st.Nlink, st.Size
	return id, Observation{sizeBytes: st.Size, allocatedBytes: st.Blocks * 512, readOnly: id.readOnly}, nil
}

func sameMount(a, b identity) bool {
	return a.mount == b.mount && a.major == b.major && a.minor == b.minor && a.filesystem == b.filesystem && a.readOnly == b.readOnly
}
