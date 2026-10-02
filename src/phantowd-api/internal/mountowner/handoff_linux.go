//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package mountowner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
	"golang.org/x/sys/unix"
)

var (
	ErrHandoffInvalid     = errors.New("invalid service-volume handoff")
	ErrHandoffUnavailable = errors.New("service-volume handoff unavailable")
	ErrHandoffBusy        = errors.New("service-volume handoff is busy")
	ErrHandoffReview      = errors.New("service-volume handoff requires review")
)

type ServiceHandoffState string

const (
	ServiceHandoffPrepared ServiceHandoffState = "prepared"
	ServiceHandoffActive   ServiceHandoffState = "active"
	ServiceHandoffReview   ServiceHandoffState = "review-required"
	ServiceHandoffClosed   ServiceHandoffState = "closed"
)

type handoffIdentity struct {
	mountID     uint64
	inode       uint64
	deviceMajor uint32
	deviceMinor uint32
	filesystem  uint32
	mountRoot   bool
}

type handoffMember struct {
	volumeID     string
	evidence     MountedVolumeEvidence
	targetBefore handoffIdentity
	bound        handoffIdentity
	directory    bool
	attempted    bool
	mounted      bool
	uncertain    bool
}

// ServiceHandoff clones qualified mount roots into one private volatile path
// tree. It retains the complete roster lease until every clone is explicitly
// detached. It does not start or stop daemons; its caller must stop all
// pathname-consuming children before Close.
type ServiceHandoff struct {
	mu              sync.Mutex
	root            *os.File
	rootPath        string
	rootIdentity    handoffIdentity
	set             *MountedVolumeSet
	required        []string
	state           ServiceHandoffState
	generation      uint64
	evidence        MountedVolumeSetEvidence
	lease           *MountedVolumeSetLease
	members         []handoffMember
	reviewRequired  bool
	resourcesClosed bool
}

// ServicePathBinding ties a service path to the exact source-volume evidence
// from which its bind-mounted clone was created. It is internal evidence.
type ServicePathBinding struct {
	VolumeID       string
	FilesystemUUID string
	SourcePath     string
	SourceMountID  uint64
	DeviceMajor    uint32
	DeviceMinor    uint32
	ReadOnly       bool
	Path           string
}

func (ServicePathBinding) MarshalJSON() ([]byte, error) {
	return nil, errors.New("service-volume handoff evidence is not serializable")
}

func (*ServicePathBinding) UnmarshalJSON([]byte) error {
	return errors.New("service-volume handoff evidence cannot be deserialized")
}

// ServicePaths is an opaque, live view of one active handoff.
type ServicePaths struct {
	handoff    *ServiceHandoff
	generation uint64
}

func (ServicePaths) MarshalJSON() ([]byte, error) {
	return nil, errors.New("service-volume paths are not serializable")
}

func (*ServicePaths) UnmarshalJSON([]byte) error {
	return errors.New("service-volume paths cannot be deserialized")
}

// NewServiceHandoff requires a pre-provisioned empty root below /run. It must
// be root-owned mode 0711: service identities may traverse the directory but
// cannot list or replace entries. Every ancestor must be root-owned, searchable
// by service identities, and not writable by group/other. Stale contents are
// never adopted.
func NewServiceHandoff(root string, set *MountedVolumeSet, volumeIDs []string) (*ServiceHandoff, error) {
	if os.Getuid() != 0 || os.Geteuid() != 0 || set == nil || !validHandoffRoot(root) ||
		volumeIDs == nil || len(volumeIDs) == 0 || len(volumeIDs) > shareconfig.MaxVolumes {
		return nil, ErrHandoffInvalid
	}
	if err := validateHandoffAncestors(root); err != nil {
		return nil, ErrHandoffInvalid
	}
	required := slices.Clone(volumeIDs)
	slices.Sort(required)
	available := make(map[string]bool, len(set.members))
	for _, member := range set.members {
		available[member.volumeID] = true
	}
	for index, id := range required {
		if !validVolumeID(id) || !available[id] || (index > 0 && required[index-1] == id) {
			return nil, ErrHandoffInvalid
		}
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, root, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, ErrHandoffUnavailable
	}
	file := os.NewFile(uintptr(fd), root)
	failed := true
	defer func() {
		if failed {
			_ = file.Close()
		}
	}()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR ||
		st.Mode&07777 != 0711 || st.Uid != 0 {
		return nil, ErrHandoffInvalid
	}
	rootIdentity, err := handoffIdentityForFD(fd)
	if err != nil || rootIdentity.mountRoot {
		return nil, ErrHandoffInvalid
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrHandoffBusy
		}
		return nil, ErrHandoffUnavailable
	}
	empty, err := handoffDirectoryEmpty(fd)
	if err != nil || !empty {
		return nil, ErrHandoffReview
	}
	handoff := &ServiceHandoff{root: file, rootPath: root, rootIdentity: rootIdentity, set: set, required: required,
		state: ServiceHandoffPrepared}
	failed = false
	return handoff, nil
}

// Mount takes one complete roster lease and attaches cloned mount trees from
// qualified O_PATH descriptors. It does not resolve source paths during the
// handoff. Ambiguous attach/verification results quarantine the handoff and
// keep its lease open.
func (h *ServiceHandoff) Mount(ctx context.Context) (ServicePaths, error) {
	if h == nil || ctx == nil {
		return ServicePaths{}, ErrHandoffInvalid
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.state != ServiceHandoffPrepared || h.resourcesClosed {
		return ServicePaths{}, ErrHandoffUnavailable
	}
	if ctx.Err() != nil {
		return ServicePaths{}, ErrHandoffUnavailable
	}
	lease, evidence, err := h.set.Acquire(ctx)
	if err != nil {
		return ServicePaths{}, err
	}
	h.lease, h.evidence, h.generation = lease, evidence, evidence.Generation()
	byID := make(map[string]MountedVolumeEvidence, len(evidence.Volumes()))
	for _, volume := range evidence.Volumes() {
		byID[volume.VolumeID()] = volume
	}
	for _, id := range h.required {
		volume, exists := byID[id]
		if !exists || volume.Compatibility() != qualifiedCompatibility || volume.MountID() == 0 || volume.DeviceMajor() == 0 {
			return ServicePaths{}, h.rejectRosterLocked(ErrHandoffReview)
		}
		h.members = append(h.members, handoffMember{volumeID: id, evidence: volume})
	}
	for index := range h.members {
		if err := ctx.Err(); err != nil {
			return ServicePaths{}, h.failBeforeOrDuringAttachLocked(err)
		}
		if err := h.attachLocked(index); err != nil {
			return ServicePaths{}, h.failBeforeOrDuringAttachLocked(err)
		}
	}
	h.state = ServiceHandoffActive
	return ServicePaths{handoff: h, generation: h.generation}, nil
}

func (h *ServiceHandoff) rejectRosterLocked(cause error) error {
	var closeErr error
	if h.lease != nil {
		closeErr = h.lease.Close()
		h.lease = nil
	}
	h.reviewRequired = true
	h.state = ServiceHandoffReview
	return errors.Join(ErrHandoffReview, cause, closeErr)
}

func (h *ServiceHandoff) attachLocked(index int) error {
	member := &h.members[index]
	if err := unix.Mkdirat(int(h.root.Fd()), member.volumeID, 0700); err != nil {
		return ErrHandoffUnavailable
	}
	member.directory = true
	target, err := openHandoffTarget(int(h.root.Fd()), member.volumeID)
	if err != nil {
		return ErrHandoffUnavailable
	}
	defer target.Close()
	before, err := handoffIdentityForFD(int(target.Fd()))
	if err != nil || before.mountRoot || before.mountID == 0 {
		return ErrHandoffUnavailable
	}
	member.targetBefore = before
	source, err := h.lease.OpenDirectory(member.volumeID, ".")
	if err != nil {
		return err
	}
	sourceIdentity, err := handoffIdentityForFD(int(source.Fd()))
	if err != nil || !sourceIdentity.mountRoot || sourceIdentity.mountID != member.evidence.mountID ||
		sourceIdentity.deviceMajor != member.evidence.deviceMajor || sourceIdentity.deviceMinor != member.evidence.deviceMinor {
		return ErrHandoffReview
	}
	treeFD, err := unix.OpenTree(int(source.Fd()), "", unix.OPEN_TREE_CLONE|unix.OPEN_TREE_CLOEXEC|unix.AT_EMPTY_PATH)
	if err != nil {
		return ErrHandoffUnavailable
	}
	tree := os.NewFile(uintptr(treeFD), "qualified-volume-mount-tree")
	member.attempted = true
	moveErr := unix.MoveMount(int(tree.Fd()), "", int(target.Fd()), "",
		unix.MOVE_MOUNT_F_EMPTY_PATH|unix.MOVE_MOUNT_T_EMPTY_PATH)
	closeErr := tree.Close()
	if moveErr != nil || closeErr != nil {
		member.uncertain = true
		return ErrHandoffReview
	}
	attached, err := openHandoffTarget(int(h.root.Fd()), member.volumeID)
	if err != nil {
		member.uncertain = true
		return ErrHandoffReview
	}
	identity, identityErr := handoffIdentityForFD(int(attached.Fd()))
	closeAttachedErr := attached.Close()
	if identityErr != nil || closeAttachedErr != nil || !sameHandoffFilesystem(sourceIdentity, identity) ||
		identity.mountID == sourceIdentity.mountID || !identity.mountRoot {
		member.uncertain = true
		return ErrHandoffReview
	}
	member.bound, member.mounted = identity, true
	return nil
}

// Verify checks both the original Owner roster and every service path. A lost
// source anchor quarantines the handoff; the service path is never rebound to
// whatever later occupies that original pathname.
func (h *ServiceHandoff) Verify() error {
	if h == nil {
		return ErrHandoffInvalid
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.state != ServiceHandoffActive || h.lease == nil {
		return ErrHandoffUnavailable
	}
	evidence, err := h.lease.Verify()
	if err != nil || evidence.Generation() != h.evidence.Generation() || evidence.Fingerprint() != h.evidence.Fingerprint() {
		h.reviewRequired = true
		h.state = ServiceHandoffReview
		return ErrHandoffReview
	}
	for _, member := range h.members {
		if !member.mounted || member.uncertain {
			h.reviewRequired = true
			h.state = ServiceHandoffReview
			return ErrHandoffReview
		}
	}
	if err := h.verifyBoundPathsLocked(); err != nil {
		h.reviewRequired = true
		h.state = ServiceHandoffReview
		return ErrHandoffReview
	}
	return nil
}

func (h *ServiceHandoff) verifyBoundPathsLocked() error {
	if h.root == nil || !h.rootPathStillPinnedLocked() {
		return ErrHandoffReview
	}
	for _, member := range h.members {
		current, err := h.observeTargetLocked(member.volumeID)
		if err != nil || current != member.bound {
			return ErrHandoffReview
		}
	}
	return nil
}

func (h *ServiceHandoff) observeTargetLocked(id string) (handoffIdentity, error) {
	file, err := openHandoffTarget(int(h.root.Fd()), id)
	if err != nil {
		return handoffIdentity{}, err
	}
	defer file.Close()
	return handoffIdentityForFD(int(file.Fd()))
}

// Paths returns an opaque, process-local view used by trusted renderers.
func (h *ServiceHandoff) Paths() (ServicePaths, error) {
	if h == nil {
		return ServicePaths{}, ErrHandoffInvalid
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.state != ServiceHandoffActive || h.resourcesClosed {
		return ServicePaths{}, ErrHandoffUnavailable
	}
	if h.lease == nil || !h.rootPathStillPinnedLocked() {
		h.reviewRequired = true
		h.state = ServiceHandoffReview
		return ServicePaths{}, ErrHandoffReview
	}
	return ServicePaths{handoff: h, generation: h.generation}, nil
}

// Bindings returns a fresh verification of the service paths. Coordinators
// should use this immediately before starting pathname-consuming processes.
func (h *ServiceHandoff) Bindings() ([]ServicePathBinding, error) {
	paths, err := h.Paths()
	if err != nil {
		return nil, err
	}
	return paths.Bindings()
}

// Bindings returns source-bound paths only while the owner remains active.
func (paths ServicePaths) Bindings() ([]ServicePathBinding, error) {
	if paths.handoff == nil {
		return nil, ErrHandoffInvalid
	}
	h := paths.handoff
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.state != ServiceHandoffActive || h.resourcesClosed || h.generation != paths.generation {
		return nil, ErrHandoffUnavailable
	}
	evidence, err := h.lease.Verify()
	if err != nil || evidence.Generation() != h.evidence.Generation() || evidence.Fingerprint() != h.evidence.Fingerprint() {
		h.reviewRequired = true
		h.state = ServiceHandoffReview
		return nil, ErrHandoffReview
	}
	if err := h.verifyBoundPathsLocked(); err != nil {
		h.reviewRequired = true
		h.state = ServiceHandoffReview
		return nil, ErrHandoffReview
	}
	bindings := make([]ServicePathBinding, 0, len(h.members))
	for _, member := range h.members {
		if !member.mounted || member.uncertain {
			return nil, ErrHandoffReview
		}
		bindings = append(bindings, ServicePathBinding{
			VolumeID: member.volumeID, FilesystemUUID: member.evidence.filesystemUUID,
			SourcePath: member.evidence.mountPath, SourceMountID: member.evidence.mountID,
			DeviceMajor: member.evidence.deviceMajor, DeviceMinor: member.evidence.deviceMinor,
			ReadOnly: member.evidence.readOnly, Path: filepath.Join(h.rootPath, member.volumeID),
		})
	}
	return bindings, nil
}

func (h *ServiceHandoff) State() ServiceHandoffState {
	if h == nil {
		return ServiceHandoffReview
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.state
}

// Close is explicit teardown after services stop. It detaches only mount roots
// whose unique identity is still the one this handoff attached. Uncertain
// results retain review and the complete roster lease; no lazy unmount/retry.
func (h *ServiceHandoff) Close() error {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.resourcesClosed {
		if h.reviewRequired {
			return ErrHandoffReview
		}
		return nil
	}
	if h.root == nil {
		h.reviewRequired = true
		h.state = ServiceHandoffReview
		return ErrHandoffReview
	}
	var cleanupErr error
	for index := len(h.members) - 1; index >= 0; index-- {
		member := &h.members[index]
		if member.uncertain {
			cleanupErr = errors.Join(cleanupErr, ErrHandoffReview)
			continue
		}
		if member.mounted {
			current, err := h.observeTargetLocked(member.volumeID)
			if err != nil || current != member.bound {
				member.uncertain = true
				cleanupErr = errors.Join(cleanupErr, ErrHandoffReview)
				continue
			}
			targetPath := fmt.Sprintf("/proc/self/fd/%d/%s", h.root.Fd(), member.volumeID)
			if err := unix.Unmount(targetPath, 0); err != nil {
				member.uncertain = true
				cleanupErr = errors.Join(cleanupErr, ErrHandoffReview)
				continue
			}
			member.mounted = false
			current, err = h.observeTargetLocked(member.volumeID)
			if err != nil || current != member.targetBefore {
				member.uncertain = true
				cleanupErr = errors.Join(cleanupErr, ErrHandoffReview)
				continue
			}
		}
		if member.directory {
			if err := unix.Unlinkat(int(h.root.Fd()), member.volumeID, unix.AT_REMOVEDIR); err != nil {
				member.uncertain = true
				cleanupErr = errors.Join(cleanupErr, ErrHandoffReview)
				continue
			}
			member.directory = false
		}
	}
	for _, member := range h.members {
		if member.mounted || member.uncertain || member.directory {
			cleanupErr = errors.Join(cleanupErr, ErrHandoffReview)
		}
	}
	if cleanupErr != nil {
		h.reviewRequired = true
		h.state = ServiceHandoffReview
		return ErrHandoffReview
	}
	if h.lease != nil {
		leaseErr := h.lease.Close()
		h.lease = nil
		if leaseErr != nil {
			h.reviewRequired = true
			h.state = ServiceHandoffReview
			return ErrHandoffReview
		}
	}
	root := h.root
	h.root = nil
	if err := root.Close(); err != nil {
		h.reviewRequired = true
		h.state = ServiceHandoffReview
		h.resourcesClosed = true
		return ErrHandoffReview
	}
	h.resourcesClosed = true
	if h.reviewRequired {
		h.state = ServiceHandoffReview
		return ErrHandoffReview
	}
	h.state = ServiceHandoffClosed
	return nil
}

func (h *ServiceHandoff) failBeforeOrDuringAttachLocked(cause error) error {
	if !anyHandoffMountAttempted(h.members) {
		var cleanupErr error
		for index := len(h.members) - 1; index >= 0; index-- {
			member := &h.members[index]
			if member.directory {
				if err := unix.Unlinkat(int(h.root.Fd()), member.volumeID, unix.AT_REMOVEDIR); err != nil {
					member.uncertain = true
					cleanupErr = errors.Join(cleanupErr, err)
				} else {
					member.directory = false
				}
			}
		}
		if cleanupErr == nil && h.lease != nil {
			cleanupErr = h.lease.Close()
			h.lease = nil
		}
		if cleanupErr == nil {
			if errors.Is(cause, ErrReview) || errors.Is(cause, ErrHandoffReview) {
				h.reviewRequired = true
				h.state = ServiceHandoffReview
				return errors.Join(ErrHandoffReview, cause)
			}
			h.state = ServiceHandoffPrepared
			return errors.Join(ErrHandoffUnavailable, cause)
		}
	}
	h.reviewRequired = true
	h.state = ServiceHandoffReview
	return errors.Join(ErrHandoffReview, cause)
}

func anyHandoffMountAttempted(members []handoffMember) bool {
	for _, member := range members {
		if member.attempted || member.mounted || member.uncertain {
			return true
		}
	}
	return false
}

func handoffDirectoryEmpty(fd int) (bool, error) {
	copyFD, err := unix.Openat(fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return false, err
	}
	file := os.NewFile(uintptr(copyFD), "service-handoff-root-check")
	defer file.Close()
	names, err := file.Readdirnames(-1)
	return len(names) == 0, err
}

func openHandoffTarget(rootFD int, volumeID string) (*os.File, error) {
	if !validVolumeID(volumeID) {
		return nil, ErrHandoffInvalid
	}
	fd, err := unix.Openat2(rootFD, volumeID, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, ErrHandoffUnavailable
	}
	return os.NewFile(uintptr(fd), "service-volume-handoff"), nil
}

func handoffIdentityForFD(fd int) (handoffIdentity, error) {
	var st unix.Statx_t
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_NO_AUTOMOUNT,
		unix.STATX_BASIC_STATS|unix.STATX_MNT_ID_UNIQUE, &st); err != nil {
		return handoffIdentity{}, ErrHandoffUnavailable
	}
	var fs unix.Statfs_t
	if err := unix.Fstatfs(fd, &fs); err != nil ||
		st.Mask&(unix.STATX_TYPE|unix.STATX_INO|unix.STATX_MNT_ID_UNIQUE) != (unix.STATX_TYPE|unix.STATX_INO|unix.STATX_MNT_ID_UNIQUE) ||
		st.Attributes_mask&unix.STATX_ATTR_MOUNT_ROOT == 0 || st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return handoffIdentity{}, ErrHandoffUnavailable
	}
	return handoffIdentity{
		mountID: st.Mnt_id, inode: st.Ino, deviceMajor: st.Dev_major, deviceMinor: st.Dev_minor,
		filesystem: uint32(fs.Type), mountRoot: st.Attributes&unix.STATX_ATTR_MOUNT_ROOT != 0,
	}, nil
}

func sameHandoffFilesystem(source, target handoffIdentity) bool {
	return source.inode == target.inode && source.deviceMajor == target.deviceMajor &&
		source.deviceMinor == target.deviceMinor && source.filesystem == target.filesystem
}

func validHandoffRoot(root string) bool {
	const prefix = "/run/phantowd/service-handoff/"
	return len(root) > len(prefix) && strings.HasPrefix(root, prefix) && filepath.IsAbs(root) &&
		filepath.Clean(root) == root && !strings.ContainsRune(root, 0)
}

func (h *ServiceHandoff) rootPathStillPinnedLocked() bool {
	if h.root == nil {
		return false
	}
	if validateHandoffAncestors(h.rootPath) != nil {
		return false
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, h.rootPath, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return false
	}
	defer unix.Close(fd)
	identity, err := handoffIdentityForFD(fd)
	var st unix.Stat_t
	return err == nil && identity == h.rootIdentity && unix.Fstat(fd, &st) == nil &&
		st.Uid == 0 && st.Mode&unix.S_IFMT == unix.S_IFDIR && st.Mode&07777 == 0711
}

func validateHandoffAncestors(root string) error {
	paths := make([]string, 0, 8)
	for current := filepath.Dir(root); current != "/"; current = filepath.Dir(current) {
		paths = append(paths, current)
	}
	for index := len(paths) - 1; index >= 0; index-- {
		fd, err := unix.Openat2(unix.AT_FDCWD, paths[index], &unix.OpenHow{
			Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC,
			Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
		})
		if err != nil {
			return err
		}
		var st unix.Stat_t
		statErr := unix.Fstat(fd, &st)
		closeErr := unix.Close(fd)
		if statErr != nil || closeErr != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 ||
			st.Mode&0022 != 0 || st.Mode&0001 == 0 {
			return ErrHandoffInvalid
		}
	}
	return nil
}
