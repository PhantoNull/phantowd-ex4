// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package mountowner

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/mountguard"
	"golang.org/x/sys/unix"
)

type modeledDriver struct {
	inspector    *modeledInspector
	mountCalls   int
	unmountCalls int
	mountError   bool
	unmountError bool
}

func (d *modeledDriver) MountBind(_, _ string) error {
	d.mountCalls++
	d.inspector.mounted = true
	if d.mountError {
		return errors.New("PRIVATE mount result lost")
	}
	return nil
}

func (d *modeledDriver) Unmount(_ string) error {
	d.unmountCalls++
	d.inspector.mounted = false
	if d.unmountError {
		return errors.New("PRIVATE unmount result lost")
	}
	return nil
}

type modeledInspector struct {
	mounted        bool
	empty          bool
	sourceExpected mountguard.Expected
	targetExpected mountguard.Expected
	targetBefore   TargetIdentity
	wrongMount     bool
	observeError   bool
}

func (i *modeledInspector) ObserveMount(path string) (mountguard.Expected, error) {
	if i.observeError {
		return mountguard.Expected{}, mountguard.ErrUnavailable
	}
	if path == "/fixture/qualified-source" {
		return i.sourceExpected, nil
	}
	if !i.mounted {
		return mountguard.Expected{}, mountguard.ErrUnavailable
	}
	result := i.targetExpected
	if i.wrongMount {
		result.FilesystemUUID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	}
	return result, nil
}

func (i *modeledInspector) ObserveTarget(string) (TargetIdentity, error) {
	if i.observeError {
		return TargetIdentity{}, mountguard.ErrUnavailable
	}
	if !i.mounted {
		return i.targetBefore, nil
	}
	return TargetIdentity{MountID: i.targetExpected.MountID, RootInode: i.targetExpected.RootInode,
		DeviceMajor: i.targetExpected.DeviceMajor, DeviceMinor: i.targetExpected.DeviceMinor,
		FilesystemType: i.targetExpected.FilesystemType, MountRoot: true}, nil
}

func (i *modeledInspector) TargetEmpty(string) (bool, error) {
	return i.empty && !i.mounted, nil
}

type modeledRoot struct {
	inspector *modeledInspector
	expected  mountguard.Expected
	closed    bool
	invalid   bool
	files     []*os.File
}

func (r *modeledRoot) Verify() error {
	if r.closed {
		return mountguard.ErrClosed
	}
	if r.invalid {
		return mountguard.ErrMismatch
	}
	observed := r.inspector.sourceExpected
	if r.expected.MountID == r.inspector.targetExpected.MountID {
		if !r.inspector.mounted {
			return mountguard.ErrMismatch
		}
		observed = r.inspector.targetExpected
	}
	if observed != r.expected {
		return mountguard.ErrMismatch
	}
	return nil
}

func (r *modeledRoot) OpenDirectory(string) (*os.File, error) {
	if err := r.Verify(); err != nil {
		return nil, err
	}
	file, err := os.Open(".")
	if err == nil {
		r.files = append(r.files, file)
	}
	return file, err
}

func (r *modeledRoot) Close() error {
	r.closed = true
	return nil
}

func mountOwnerFixture(t *testing.T) (*Owner, *Qualification, *modeledDriver, *modeledInspector, *modeledRoot) {
	t.Helper()
	inspector := &modeledInspector{empty: true,
		targetBefore: TargetIdentity{MountID: 100, RootInode: 200, DeviceMajor: 0, DeviceMinor: 22,
			FilesystemType: uint32(unix.TMPFS_MAGIC), MountRootKnown: true},
		sourceExpected: mountguard.Expected{MountID: 101, RootInode: 2, DeviceMajor: 8, DeviceMinor: 17,
			FilesystemType: uint32(unix.EXT4_SUPER_MAGIC), FilesystemUUID: "11111111-2222-3333-4444-555555555555", RequireWritable: true},
		targetExpected: mountguard.Expected{MountID: 102, RootInode: 2, DeviceMajor: 8, DeviceMinor: 17,
			FilesystemType: uint32(unix.EXT4_SUPER_MAGIC), FilesystemUUID: "11111111-2222-3333-4444-555555555555", RequireWritable: true}}
	driver := &modeledDriver{inspector: inspector}
	sourceRoot := &modeledRoot{inspector: inspector, expected: inspector.sourceExpected}
	qualification := &Qualification{volumeID: "fixture-volume", source: "/fixture/qualified-source", expected: inspector.sourceExpected, sourceRoot: sourceRoot}
	var targetRoot *modeledRoot
	owner, err := newOwner("/fixture/target", driver, inspector, func(_ string, expected mountguard.Expected) (rootGuard, error) {
		if !inspector.mounted || inspector.wrongMount || expected != inspector.targetExpected {
			return nil, mountguard.ErrMismatch
		}
		targetRoot = &modeledRoot{inspector: inspector, expected: expected}
		return targetRoot, nil
	})
	if err != nil {
		t.Fatal("open modeled mount owner:", err)
	}
	return owner, qualification, driver, inspector, sourceRoot
}

func TestLeaseRequiresTrustedQualificationAndCompletedMount(t *testing.T) {
	owner, qualification, driver, _, sourceRoot := mountOwnerFixture(t)
	if _, err := owner.Acquire(context.Background()); !errors.Is(err, ErrUnavailable) || driver.mountCalls != 0 {
		t.Fatal("lease was issued before qualification/mount:", err)
	}
	if err := owner.Qualify(qualification); err != nil || owner.State() != StateQualified {
		t.Fatal("trusted fixture did not qualify:", owner.State(), err)
	}
	if err := owner.Mount(context.Background()); err != nil || owner.State() != StateMounted {
		t.Fatal("qualified fixture did not mount:", owner.State(), err)
	}
	if !sourceRoot.closed || driver.mountCalls != 1 {
		t.Fatal("source qualification was not consumed exactly once")
	}
	lease, err := owner.Acquire(context.Background())
	if err != nil {
		t.Fatal("qualified mounted root refused lease:", err)
	}
	file, err := lease.OpenDirectory(".")
	if err != nil {
		t.Fatal("qualified lease could not resolve its root:", err)
	}
	if _, err := file.Read(make([]byte, 1)); err == nil {
		file.Close()
		t.Fatal("mount owner returned a content-readable descriptor")
	}
	if err := owner.Drain(); !errors.Is(err, ErrBusy) || owner.State() != StateDraining {
		t.Fatal("drain did not block new leases while an existing lease remained:", owner.State(), err)
	}
	if _, err := lease.OpenDirectory("."); !errors.Is(err, ErrUnavailable) {
		t.Fatal("draining owner allowed a new directory operation through an existing lease:", err)
	}
	if _, err := owner.Acquire(context.Background()); !errors.Is(err, ErrBusy) {
		t.Fatal("draining owner issued a new lease:", err)
	}
	if err := owner.Unmount(context.Background()); !errors.Is(err, ErrBusy) || driver.unmountCalls != 0 {
		t.Fatal("owner unmounted while a lease remained:", err, driver.unmountCalls)
	}
	if err := lease.Close(); err != nil {
		t.Fatal("release lease:", err)
	}
	if err := owner.Unmount(context.Background()); err != nil || owner.State() != StateUnavailable || driver.unmountCalls != 1 {
		t.Fatal("owner did not perform one verified unmount:", owner.State(), err, driver.unmountCalls)
	}
}

func TestQualificationTokenCannotBeConsumedTwice(t *testing.T) {
	owner, qualification, _, inspector, sourceRoot := mountOwnerFixture(t)
	if err := owner.Qualify(qualification); err != nil {
		t.Fatal("first owner failed to consume trusted qualification:", err)
	}
	second, err := newOwner("/fixture/other-target", &modeledDriver{inspector: inspector}, inspector,
		func(_ string, expected mountguard.Expected) (rootGuard, error) {
			return &modeledRoot{inspector: inspector, expected: expected}, nil
		})
	if err != nil {
		t.Fatal("open second owner:", err)
	}
	if err := second.Qualify(qualification); !errors.Is(err, ErrRejected) {
		t.Fatal("second owner reused a consumed qualification:", err)
	}
	if sourceRoot.closed {
		t.Fatal("rejected token reuse revoked the first owner's source guard")
	}
	if err := owner.Mount(context.Background()); err != nil || owner.State() != StateMounted {
		t.Fatal("first owner lost its qualification after rejected reuse:", err)
	}
}

func TestIdentityChangeRevokesNewAndOwnerHeldAccess(t *testing.T) {
	owner, qualification, _, inspector, sourceRoot := mountOwnerFixture(t)
	if err := owner.Qualify(qualification); err != nil || owner.Mount(context.Background()) != nil {
		t.Fatal("mount fixture setup failed", err)
	}
	lease, err := owner.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	file, err := lease.OpenDirectory(".")
	if err != nil {
		t.Fatal(err)
	}
	root := owner.root.(*modeledRoot)
	root.invalid = true
	if _, err := owner.Acquire(context.Background()); !errors.Is(err, ErrReview) || owner.State() != StateReviewRequired {
		t.Fatal("changed mount identity did not quarantine the owner:", owner.State(), err)
	}
	if _, err := file.Stat(); err == nil {
		t.Fatal("identity change did not close Owner-held directory references")
	}
	if _, err := owner.Acquire(context.Background()); !errors.Is(err, ErrReview) {
		t.Fatal("quarantined mount owner issued a new lease:", err)
	}
	if !sourceRoot.closed || inspector.mounted == false {
		t.Fatal("identity change unexpectedly cleaned up or retained the source authority")
	}
	if err := owner.Unmount(context.Background()); !errors.Is(err, ErrReview) {
		t.Fatal("identity change allowed an uncertain automatic unmount:", err)
	}
}

func TestAmbiguousMountResultRequiresReviewWithoutRetry(t *testing.T) {
	owner, qualification, driver, inspector, _ := mountOwnerFixture(t)
	driver.mountError = true
	if err := owner.Qualify(qualification); err != nil {
		t.Fatal(err)
	}
	if err := owner.Mount(context.Background()); !errors.Is(err, ErrReview) || owner.State() != StateReviewRequired {
		t.Fatal("ambiguous mount result was not quarantined:", owner.State(), err)
	}
	if _, err := owner.Acquire(context.Background()); !errors.Is(err, ErrReview) || driver.mountCalls != 1 {
		t.Fatal("ambiguous mount was retried or leased:", err, driver.mountCalls)
	}
	if !inspector.mounted {
		t.Fatal("fixture did not model a mount with a lost result")
	}
}

func TestAmbiguousUnmountResultRequiresReviewWithoutRetry(t *testing.T) {
	owner, qualification, driver, inspector, _ := mountOwnerFixture(t)
	if err := owner.Qualify(qualification); err != nil || owner.Mount(context.Background()) != nil {
		t.Fatal("mount fixture setup failed", err)
	}
	if err := owner.Drain(); err != nil {
		t.Fatal("begin drain:", err)
	}
	driver.unmountError = true
	if err := owner.Unmount(context.Background()); !errors.Is(err, ErrReview) || owner.State() != StateReviewRequired {
		t.Fatal("ambiguous unmount result was not quarantined:", owner.State(), err)
	}
	if err := owner.Unmount(context.Background()); !errors.Is(err, ErrReview) || driver.unmountCalls != 1 {
		t.Fatal("ambiguous unmount was retried:", err, driver.unmountCalls)
	}
	if inspector.mounted {
		t.Fatal("fixture did not model an unmount with a lost result")
	}
}

func TestMismatchedMountedFilesystemGetsNoLease(t *testing.T) {
	owner, qualification, driver, inspector, _ := mountOwnerFixture(t)
	inspector.wrongMount = true
	if err := owner.Qualify(qualification); err != nil {
		t.Fatal(err)
	}
	if err := owner.Mount(context.Background()); !errors.Is(err, ErrReview) || driver.mountCalls != 1 {
		t.Fatal("mismatched filesystem was not quarantined:", owner.State(), err)
	}
	if _, err := owner.Acquire(context.Background()); !errors.Is(err, ErrReview) {
		t.Fatal("mismatched filesystem received a lease:", err)
	}
}
