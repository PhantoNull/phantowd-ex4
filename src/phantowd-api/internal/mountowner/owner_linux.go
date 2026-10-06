// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package mountowner is an internal, single-owner mount lifecycle prototype.
// It is not wired to an HTTP/RPC endpoint or a product storage qualifier.
package mountowner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/mountguard"
)

var (
	ErrInvalid     = errors.New("invalid mount-owner request")
	ErrUnavailable = errors.New("qualified mount unavailable")
	ErrBusy        = errors.New("mount owner has outstanding leases")
	ErrConflict    = errors.New("mount-owner state conflict")
	ErrRejected    = errors.New("mount candidate rejected")
	ErrReview      = errors.New("mount outcome requires review")
)

type State string

const qualifiedCompatibility = "qualified"

const (
	StateAbsent         State = "absent"
	StateDiscovered     State = "discovered"
	StateRejected       State = "rejected"
	StateQualified      State = "qualified"
	StateMounting       State = "mounting"
	StateMounted        State = "mounted"
	StateUnavailable    State = "unavailable"
	StateDraining       State = "draining"
	StateReviewRequired State = "review-required"
)

// TargetIdentity is the transient mountpoint identity before and after a
// lifecycle operation. It is not a disk or volume identity and must not be
// persisted or accepted from an external request.
type TargetIdentity struct {
	MountID        uint64
	RootInode      uint64
	DeviceMajor    uint32
	DeviceMinor    uint32
	FilesystemType uint32
	MountRoot      bool
	MountRootKnown bool
}

// Driver is fixed when an Owner is created. Product code must supply only a
// reviewed, fixed-path implementation; request handlers must never provide or
// substitute it. Mount and unmount errors are treated as ambiguous outcomes.
type Driver interface {
	MountBind(source, target *os.File) error
	Unmount(target string) error
}

// Observer reads only current kernel mount identity and pins the pre-created
// mountpoint for identity/emptiness checks. It must not mount, open block
// devices, or infer intended filesystem identity from the target.
type Observer interface {
	ObserveMount(path string) (mountguard.Expected, error)
	ObserveTarget(path string) (TargetIdentity, error)
	PinTarget(path string) (targetHandle, error)
}

// targetHandle pins the exact pre-created mountpoint object. Its file is an
// O_PATH directory descriptor used only by the fixed mount driver; it is not
// returned to callers or used to resolve arbitrary child paths.
type targetHandle interface {
	Identity() (TargetIdentity, error)
	Empty() (bool, error)
	File() *os.File
	Close() error
}

type rootGuard interface {
	Verify() error
	OpenDirectory(string) (*os.File, error)
	Close() error
}

type rootOpener func(string, mountguard.Expected) (rootGuard, error)

// Qualification is a one-use capability minted by trusted in-process code.
// Its fields are intentionally private: current production code has no
// constructor, and the only current constructor is compiled into QEMU tests.
// The tuple is transient to one kernel/mount namespace; never serialize it.
type Qualification struct {
	mu            sync.Mutex
	volumeID      string
	compatibility string
	source        string
	expected      mountguard.Expected
	sourceRoot    rootGuard
	consumed      bool
}

// MountedVolumeEvidence is a process-local, non-serializable observation of
// one currently mounted volume owned by this lifecycle coordinator. It does
// not assert that the caller has discovered every volume and grants no file or
// mount authority. Construct it only by revalidating a mounted Owner.
type MountedVolumeEvidence struct {
	volumeID       string
	filesystemUUID string
	mountPath      string
	compatibility  string
	generation     uint64
	mountID        uint64
	deviceMajor    uint32
	deviceMinor    uint32
	readOnly       bool
}

func (e MountedVolumeEvidence) VolumeID() string       { return e.volumeID }
func (e MountedVolumeEvidence) FilesystemUUID() string { return e.filesystemUUID }
func (e MountedVolumeEvidence) MountPath() string      { return e.mountPath }
func (e MountedVolumeEvidence) Compatibility() string  { return e.compatibility }
func (e MountedVolumeEvidence) Generation() uint64     { return e.generation }
func (e MountedVolumeEvidence) MountID() uint64        { return e.mountID }
func (e MountedVolumeEvidence) DeviceMajor() uint32    { return e.deviceMajor }
func (e MountedVolumeEvidence) DeviceMinor() uint32    { return e.deviceMinor }
func (e MountedVolumeEvidence) ReadOnly() bool         { return e.readOnly }
func (MountedVolumeEvidence) MarshalJSON() ([]byte, error) {
	return nil, errors.New("internal mounted-volume evidence is not serializable")
}
func (*MountedVolumeEvidence) UnmarshalJSON([]byte) error {
	return errors.New("internal mounted-volume evidence cannot be deserialized")
}

// Mounts are not inferred from directory names. The owner retains all authority
// and lease bookkeeping under one non-queuing mutex. Never copy an Owner.
type Owner struct {
	mu            sync.Mutex
	target        string
	driver        Driver
	observer      Observer
	openRoot      rootOpener
	state         State
	qualification *Qualification
	targetBefore  TargetIdentity
	targetPin     targetHandle
	expected      mountguard.Expected
	root          rootGuard
	leases        map[*Lease]struct{}
	generation    uint64
	volumeID      string
	compatibility string
}

// Lease is an Owner-tracked, revocable metadata-only handle. A lease cannot
// mount, unmount, or return an untracked descriptor.
type Lease struct {
	owner      *Owner
	generation uint64
	closed     bool
	files      map[*os.File]struct{}
}

// newOwner is internal so a caller cannot construct a production lifecycle
// without reviewed in-process dependencies. It does not create the target.
func newOwner(target string, driver Driver, observer Observer, openRoot rootOpener) (*Owner, error) {
	if !validAbsolute(target) || driver == nil || observer == nil || openRoot == nil {
		return nil, ErrInvalid
	}
	return &Owner{target: target, driver: driver, observer: observer, openRoot: openRoot,
		state: StateAbsent, leases: make(map[*Lease]struct{})}, nil
}

// Qualify verifies a one-use trusted token against its currently mounted
// source, then captures an empty, non-mount-root destination. It performs no
// mount and issues no lease.
func (o *Owner) Qualify(qualification *Qualification) error {
	if o == nil {
		return ErrInvalid
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.state != StateAbsent && o.state != StateUnavailable {
		return stateError(o.state)
	}
	o.state = StateDiscovered
	if qualification != nil {
		qualification.mu.Lock()
		defer qualification.mu.Unlock()
	}
	if qualification == nil {
		return o.rejectQualification(nil)
	}
	if qualification.consumed {
		// A consumed token's guard now belongs to the first Owner. Reject reuse
		// without invalidating that Owner's live qualification.
		o.state = StateRejected
		return ErrRejected
	}
	if !validVolumeID(qualification.volumeID) || qualification.compatibility != qualifiedCompatibility ||
		!validAbsolute(qualification.source) || qualification.source == o.target ||
		qualification.sourceRoot == nil || !validExpected(qualification.expected) || sameOrNestedPath(qualification.source, o.target) {
		return o.rejectQualification(qualification)
	}
	if err := qualification.sourceRoot.Verify(); err != nil {
		return o.rejectQualification(qualification)
	}
	observedSource, err := o.observer.ObserveMount(qualification.source)
	if err != nil || !sameKernelMount(observedSource, qualification.expected) {
		return o.rejectQualification(qualification)
	}
	target, err := o.observer.ObserveTarget(o.target)
	if err != nil || !target.MountRootKnown || target.MountRoot || target.MountID == 0 || target.RootInode == 0 {
		return o.rejectQualification(qualification)
	}
	pin, err := o.observer.PinTarget(o.target)
	if err != nil || pin == nil {
		if pin != nil {
			_ = pin.Close()
		}
		return o.rejectQualification(qualification)
	}
	o.targetPin = pin
	pinnedIdentity, err := pin.Identity()
	if err != nil || pinnedIdentity != target {
		return o.rejectQualification(qualification)
	}
	empty, err := pin.Empty()
	if err != nil || !empty {
		return o.rejectQualification(qualification)
	}
	qualification.consumed = true
	o.qualification = qualification
	o.targetBefore = target
	o.state = StateQualified
	return nil
}

// Mount performs exactly one fixed bind operation. Once the driver is called,
// every error/cancellation/identity uncertainty becomes review-required; the
// owner never tries an implicit cleanup or replays a mount.
func (o *Owner) Mount(ctx context.Context) error {
	if o == nil || ctx == nil {
		return ErrInvalid
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.state != StateQualified || o.qualification == nil {
		return stateError(o.state)
	}
	if ctx.Err() != nil {
		return ErrUnavailable
	}
	if err := o.qualification.sourceRoot.Verify(); err != nil || !o.targetUnchangedAndEmptyLocked() {
		return o.rejectQualification(o.qualification)
	}
	source, err := o.qualification.sourceRoot.OpenDirectory(".")
	if err != nil || source == nil || o.targetPin == nil || o.targetPin.File() == nil {
		if source != nil {
			_ = source.Close()
		}
		return o.rejectQualification(o.qualification)
	}
	o.state = StateMounting
	mountErr := o.driver.MountBind(source, o.targetPin.File())
	sourceCloseErr := source.Close()
	if mountErr != nil || sourceCloseErr != nil || ctx.Err() != nil {
		return o.reviewLocked()
	}
	observed, err := o.observer.ObserveMount(o.target)
	if err != nil || !sameMountedFilesystem(observed, o.qualification.expected) {
		return o.reviewLocked()
	}
	// The filesystem UUID is trusted qualification context: statx/statfs expose
	// mount/device/root identity but do not independently report the UUID.
	observed.FilesystemUUID = o.qualification.expected.FilesystemUUID
	observed.RequireWritable = o.qualification.expected.RequireWritable
	root, err := o.openRoot(o.target, observed)
	if err != nil {
		return o.reviewLocked()
	}
	if err := o.qualification.sourceRoot.Verify(); err != nil || root.Verify() != nil || !o.mountedIdentityUnchangedLocked(observed) {
		root.Close()
		return o.reviewLocked()
	}
	if err := o.qualification.sourceRoot.Close(); err != nil {
		root.Close()
		return o.reviewLocked()
	}
	o.qualification.sourceRoot = nil
	o.root = root
	o.expected = observed
	o.volumeID = o.qualification.volumeID
	o.compatibility = o.qualification.compatibility
	o.qualification = nil
	o.generation++
	o.state = StateMounted
	return nil
}

// Acquire issues a lease only while the exact qualified mount remains present.
func (o *Owner) Acquire(ctx context.Context) (*Lease, error) {
	if o == nil || ctx == nil {
		return nil, ErrInvalid
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.acquireLocked(ctx)
}

// acquireLocked requires o.mu. MountedVolumeSet uses it while every member
// Owner is held, so a caller receives either a lease for the complete roster
// or no leases at all.
func (o *Owner) acquireLocked(ctx context.Context) (*Lease, error) {
	if ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	if o.state != StateMounted {
		return nil, stateError(o.state)
	}
	if err := o.verifyMountedLocked(); err != nil {
		return nil, err
	}
	lease := &Lease{owner: o, generation: o.generation, files: make(map[*os.File]struct{})}
	o.leases[lease] = struct{}{}
	return lease, nil
}

// Verify detects lost/replaced/read-only mounts and permanently quarantines
// this owner. A fresh trusted qualification and Owner are required afterward.
func (o *Owner) Verify() error {
	if o == nil {
		return ErrInvalid
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.state != StateMounted && o.state != StateDraining {
		return stateError(o.state)
	}
	return o.verifyMountedLocked()
}

// Drain stops new lease use. Existing leases must be closed before unmount.
// ErrBusy leaves the owner in Draining, so no replacement access is admitted.
func (o *Owner) Drain() error {
	if o == nil {
		return ErrInvalid
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.state != StateMounted {
		return stateError(o.state)
	}
	if err := o.verifyMountedLocked(); err != nil {
		return err
	}
	o.state = StateDraining
	if len(o.leases) != 0 {
		return ErrBusy
	}
	return nil
}

// Unmount consumes the draining state exactly once. Any syscall result or
// postcondition that is uncertain moves to review-required without retry.
func (o *Owner) Unmount(ctx context.Context) error {
	if o == nil || ctx == nil {
		return ErrInvalid
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.state == StateReviewRequired {
		return ErrReview
	}
	if o.state != StateDraining {
		return stateError(o.state)
	}
	if len(o.leases) != 0 {
		return ErrBusy
	}
	if ctx.Err() != nil {
		return ErrUnavailable
	}
	if err := o.verifyMountedLocked(); err != nil {
		return err
	}
	// Drop the pinned O_PATH root only after its identity was just verified;
	// keeping it open can make a normal umount report EBUSY. If closing fails,
	// quarantine before making any mount-table change.
	if o.root != nil {
		if err := o.root.Close(); err != nil {
			return o.reviewLocked()
		}
		o.root = nil
	}
	if err := o.driver.Unmount(o.target); err != nil || ctx.Err() != nil {
		return o.reviewLocked()
	}
	after, err := o.observer.ObserveTarget(o.target)
	if err != nil || after != o.targetBefore {
		return o.reviewLocked()
	}
	if o.targetPin == nil {
		return o.reviewLocked()
	}
	pinnedIdentity, err := o.targetPin.Identity()
	if err != nil || pinnedIdentity != o.targetBefore {
		return o.reviewLocked()
	}
	empty, err := o.targetPin.Empty()
	if err != nil || !empty {
		return o.reviewLocked()
	}
	if err := o.closeTargetLocked(); err != nil {
		return o.reviewLocked()
	}
	o.state = StateUnavailable
	o.volumeID, o.compatibility = "", ""
	return nil
}

// Close revokes Owner-managed directory references. It deliberately does not
// mount or unmount; closing an owner while mounted is therefore quarantined.
func (o *Owner) Close() error {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.state == StateMounted || o.state == StateDraining || o.state == StateMounting {
		o.reviewLocked()
		return nil
	}
	o.closeQualificationLocked()
	o.closeLeasedFilesLocked()
	if o.root != nil {
		o.root.Close()
		o.root = nil
	}
	_ = o.closeTargetLocked()
	if o.state != StateReviewRequired {
		o.state = StateUnavailable
	}
	return nil
}

func (o *Owner) State() State {
	if o == nil {
		return StateUnavailable
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.state
}

// ObserveMountedVolume rechecks the live kernel mount identity while holding
// the lifecycle lock and returns only this Owner's current per-volume tuple.
// It is intentionally not a complete storage inventory and returns no lease.
func (o *Owner) ObserveMountedVolume() (MountedVolumeEvidence, error) {
	if o == nil {
		return MountedVolumeEvidence{}, ErrInvalid
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.observeMountedVolumeLocked()
}

// observeMountedVolumeLocked must be called with o.mu held. Keeping the
// revalidation in this helper lets MountedVolumeSet lock every member before
// observing any of them, producing one coherent all-or-error snapshot.
func (o *Owner) observeMountedVolumeLocked() (MountedVolumeEvidence, error) {
	if o.state != StateMounted {
		return MountedVolumeEvidence{}, stateError(o.state)
	}
	if err := o.verifyMountedLocked(); err != nil {
		return MountedVolumeEvidence{}, err
	}
	if !validVolumeID(o.volumeID) || o.compatibility != qualifiedCompatibility ||
		!validAbsolute(o.target) || o.generation == 0 || !validExpected(o.expected) ||
		o.expected.MountID == 0 || o.expected.DeviceMajor == 0 {
		return MountedVolumeEvidence{}, o.reviewLocked()
	}
	return MountedVolumeEvidence{
		volumeID: o.volumeID, filesystemUUID: o.expected.FilesystemUUID, mountPath: o.target,
		compatibility: o.compatibility, generation: o.generation, mountID: o.expected.MountID,
		deviceMajor: o.expected.DeviceMajor, deviceMinor: o.expected.DeviceMinor,
		readOnly: !o.expected.RequireWritable,
	}, nil
}

// OpenDirectory resolves an existing metadata-only directory through the
// qualified mount. Draining blocks new opens; descriptors already returned
// remain Owner-tracked and are closed by lease release or quarantine.
func (l *Lease) OpenDirectory(relative string) (*os.File, error) {
	if l == nil || l.owner == nil {
		return nil, ErrUnavailable
	}
	o := l.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	_, active := o.leases[l]
	if l.closed || l.generation != o.generation || !active {
		return nil, ErrUnavailable
	}
	if o.state != StateMounted {
		if o.state == StateReviewRequired {
			return nil, ErrReview
		}
		return nil, ErrUnavailable
	}
	if err := o.verifyMountedLocked(); err != nil {
		return nil, err
	}
	file, err := o.root.OpenDirectory(relative)
	if err != nil {
		if o.root == nil || o.root.Verify() != nil || !o.mountedIdentityUnchangedLocked(o.expected) {
			return nil, o.reviewLocked()
		}
		return nil, err
	}
	if o.root.Verify() != nil || !o.mountedIdentityUnchangedLocked(o.expected) {
		file.Close()
		return nil, o.reviewLocked()
	}
	l.files[file] = struct{}{}
	return file, nil
}

// Close releases every descriptor issued through this lease. It never
// unmounts; the Owner must be explicitly drained and unmounted separately.
func (l *Lease) Close() error {
	if l == nil || l.owner == nil {
		return nil
	}
	o := l.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	return l.closeLocked()
}

// closeLocked requires l.owner.mu. It removes the lease even when descriptor
// close reports an error; the caller must quarantine that Owner on uncertainty.
func (l *Lease) closeLocked() error {
	if l == nil || l.owner == nil {
		return nil
	}
	o := l.owner
	if l.closed {
		return nil
	}
	closeErr := l.closeFilesLocked()
	l.closed = true
	delete(o.leases, l)
	return closeErr
}

func (l *Lease) closeFilesLocked() error {
	var result error
	for file := range l.files {
		if err := file.Close(); err != nil {
			result = errors.Join(result, ErrUnavailable)
		}
		delete(l.files, file)
	}
	return result
}

func (o *Owner) verifyMountedLocked() error {
	if o.root == nil || o.root.Verify() != nil || !o.mountedIdentityUnchangedLocked(o.expected) {
		return o.reviewLocked()
	}
	return nil
}

func (o *Owner) mountedIdentityUnchangedLocked(expected mountguard.Expected) bool {
	observed, err := o.observer.ObserveMount(o.target)
	return err == nil && sameKernelMount(observed, expected)
}

func (o *Owner) targetUnchangedAndEmptyLocked() bool {
	target, err := o.observer.ObserveTarget(o.target)
	if err != nil || target != o.targetBefore || target.MountRoot || !target.MountRootKnown {
		return false
	}
	if o.targetPin == nil {
		return false
	}
	pinnedIdentity, err := o.targetPin.Identity()
	if err != nil || pinnedIdentity != o.targetBefore {
		return false
	}
	empty, err := o.targetPin.Empty()
	return err == nil && empty
}

func (o *Owner) rejectQualification(qualification *Qualification) error {
	o.state = StateRejected
	o.volumeID, o.compatibility = "", ""
	if qualification != nil && qualification.sourceRoot != nil {
		qualification.sourceRoot.Close()
		qualification.sourceRoot = nil
		qualification.consumed = true
	}
	_ = o.closeTargetLocked()
	o.qualification = nil
	return ErrRejected
}

func (o *Owner) reviewLocked() error {
	o.state = StateReviewRequired
	o.volumeID, o.compatibility = "", ""
	o.closeQualificationLocked()
	if o.root != nil {
		o.root.Close()
		o.root = nil
	}
	_ = o.closeTargetLocked()
	o.closeLeasedFilesLocked()
	return ErrReview
}

func (o *Owner) closeTargetLocked() error {
	if o.targetPin == nil {
		return nil
	}
	pin := o.targetPin
	o.targetPin = nil
	if err := pin.Close(); err != nil {
		return ErrUnavailable
	}
	return nil
}

func (o *Owner) closeQualificationLocked() {
	if o.qualification != nil && o.qualification.sourceRoot != nil {
		o.qualification.sourceRoot.Close()
		o.qualification.sourceRoot = nil
	}
	if o.qualification != nil {
		o.qualification.consumed = true
	}
	o.qualification = nil
}

func (o *Owner) closeLeasedFilesLocked() {
	for lease := range o.leases {
		lease.closeFilesLocked()
	}
}

func stateError(state State) error {
	if state == StateReviewRequired {
		return ErrReview
	}
	if state == StateRejected {
		return ErrRejected
	}
	if state == StateDraining || state == StateMounting {
		return ErrBusy
	}
	if state == StateQualified || state == StateMounted {
		return ErrConflict
	}
	return ErrUnavailable
}

func validExpected(expected mountguard.Expected) bool {
	return expected.MountID != 0 && expected.RootInode != 0 && expected.FilesystemType != 0 &&
		expected.DeviceMajor != 0 && validUUID(expected.FilesystemUUID)
}

func validUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for index, char := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if char != '-' {
				return false
			}
			continue
		}
		if !(char >= '0' && char <= '9') && !(char >= 'a' && char <= 'f') {
			return false
		}
	}
	return true
}

func sameKernelMount(left, right mountguard.Expected) bool {
	return left.MountID == right.MountID && left.RootInode == right.RootInode &&
		left.DeviceMajor == right.DeviceMajor && left.DeviceMinor == right.DeviceMinor &&
		left.FilesystemType == right.FilesystemType && left.RequireWritable == right.RequireWritable &&
		(left.FilesystemUUID == "" || left.FilesystemUUID == right.FilesystemUUID)
}

func sameMountedFilesystem(actual, source mountguard.Expected) bool {
	return actual.MountID != 0 && actual.MountID != source.MountID && actual.RootInode == source.RootInode &&
		actual.DeviceMajor == source.DeviceMajor && actual.DeviceMinor == source.DeviceMinor &&
		actual.FilesystemType == source.FilesystemType && actual.RequireWritable == source.RequireWritable &&
		(actual.FilesystemUUID == "" || actual.FilesystemUUID == source.FilesystemUUID)
}

func validVolumeID(id string) bool {
	if len(id) == 0 || len(id) > 64 || id[0] < 'a' || id[0] > 'z' {
		return false
	}
	for _, char := range id[1:] {
		if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
			return false
		}
	}
	return true
}

func validAbsolute(path string) bool {
	return path != "" && path != "/" && len(path) <= 4096 && filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.ContainsRune(path, 0)
}

func sameOrNestedPath(source, target string) bool {
	return pathContains(source, target) || pathContains(target, source)
}

func pathContains(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	if err != nil {
		return true
	}
	return rel == "." || rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
