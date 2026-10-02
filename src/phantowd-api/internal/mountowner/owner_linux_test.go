// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package mountowner

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

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

func (d *modeledDriver) MountBind(source, target *os.File) error {
	if source == nil || target == nil {
		return ErrInvalid
	}
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
	observeHook    func(string)
}

func (i *modeledInspector) ObserveMount(path string) (mountguard.Expected, error) {
	if i.observeHook != nil {
		i.observeHook(path)
	}
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

func (i *modeledInspector) PinTarget(string) (targetHandle, error) {
	fd, err := unix.Open(".", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return &modeledTarget{inspector: i, file: os.NewFile(uintptr(fd), "modeled-target")}, nil
}

type modeledTarget struct {
	inspector *modeledInspector
	file      *os.File
}

func (t *modeledTarget) Identity() (TargetIdentity, error) {
	if t.file == nil {
		return TargetIdentity{}, mountguard.ErrClosed
	}
	if _, err := t.file.Stat(); err != nil {
		return TargetIdentity{}, err
	}
	return t.inspector.targetBefore, nil
}

func (t *modeledTarget) Empty() (bool, error) {
	if t.file == nil {
		return false, mountguard.ErrClosed
	}
	return t.inspector.empty && !t.inspector.mounted, nil
}

func (t *modeledTarget) File() *os.File { return t.file }

func (t *modeledTarget) Close() error {
	if t.file == nil {
		return nil
	}
	err := t.file.Close()
	t.file = nil
	return err
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
	fd, err := unix.Open(".", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "modeled-qualified-directory")
	r.files = append(r.files, file)
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
	qualification := &Qualification{volumeID: "fixture-volume", compatibility: qualifiedCompatibility,
		source: "/fixture/qualified-source", expected: inspector.sourceExpected, sourceRoot: sourceRoot}
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

func mountedOwnerFixtureForSet(t *testing.T, volumeID, target, uuid string, sourceMountID, mountedMountID uint64, deviceMinor uint32) (*Owner, *modeledInspector) {
	t.Helper()
	inspector := &modeledInspector{empty: true,
		targetBefore: TargetIdentity{MountID: 100, RootInode: 200 + uint64(deviceMinor), DeviceMajor: 0, DeviceMinor: 22,
			FilesystemType: uint32(unix.TMPFS_MAGIC), MountRootKnown: true},
		sourceExpected: mountguard.Expected{MountID: sourceMountID, RootInode: 2, DeviceMajor: 8, DeviceMinor: deviceMinor,
			FilesystemType: uint32(unix.EXT4_SUPER_MAGIC), FilesystemUUID: uuid, RequireWritable: true},
		targetExpected: mountguard.Expected{MountID: mountedMountID, RootInode: 2, DeviceMajor: 8, DeviceMinor: deviceMinor,
			FilesystemType: uint32(unix.EXT4_SUPER_MAGIC), FilesystemUUID: uuid, RequireWritable: true}}
	driver := &modeledDriver{inspector: inspector}
	sourceRoot := &modeledRoot{inspector: inspector, expected: inspector.sourceExpected}
	qualification := &Qualification{volumeID: volumeID, compatibility: qualifiedCompatibility,
		source: "/fixture/qualified-source", expected: inspector.sourceExpected, sourceRoot: sourceRoot}
	owner, err := newOwner(target, driver, inspector, func(_ string, expected mountguard.Expected) (rootGuard, error) {
		if !inspector.mounted || inspector.wrongMount || expected != inspector.targetExpected {
			return nil, mountguard.ErrMismatch
		}
		return &modeledRoot{inspector: inspector, expected: expected}, nil
	})
	if err != nil {
		t.Fatal("open mounted-set fixture owner:", err)
	}
	if err := owner.Qualify(qualification); err != nil {
		t.Fatal("qualify mounted-set fixture:", err)
	}
	if err := owner.Mount(context.Background()); err != nil {
		t.Fatal("mount mounted-set fixture:", err)
	}
	t.Cleanup(func() {
		if owner.State() == StateMounted {
			if err := owner.Drain(); err == nil {
				if err := owner.Unmount(context.Background()); err != nil {
					t.Errorf("unmount mounted-set fixture: %v", err)
				}
			}
		}
		_ = owner.Close()
	})
	return owner, inspector
}

func TestMountedVolumeSetObservesFixedRosterAndAdvancesGeneration(t *testing.T) {
	alpha, _ := mountedOwnerFixtureForSet(t, "alpha", "/srv/phantowd/volumes/alpha",
		"11111111-2222-3333-4444-555555555555", 101, 102, 17)
	beta, _ := mountedOwnerFixtureForSet(t, "beta", "/srv/phantowd/volumes/beta",
		"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", 201, 202, 33)
	set, err := newMountedVolumeSet([]string{"beta", "alpha"}, []*Owner{beta, alpha})
	if err != nil {
		t.Fatal("create fixed mounted-volume roster:", err)
	}

	first, err := set.Observe()
	if err != nil || !first.Complete() || first.Generation() != 1 || len(first.Volumes()) != 2 {
		t.Fatalf("first complete mounted-set observation: complete=%v generation=%d count=%d err=%v",
			first.Complete(), first.Generation(), len(first.Volumes()), err)
	}
	volumes := first.Volumes()
	if volumes[0].VolumeID() != "alpha" || volumes[1].VolumeID() != "beta" ||
		first.Fingerprint() == [32]byte{} {
		t.Fatalf("mounted set is not canonical and fingerprinted: ids=%s,%s", volumes[0].VolumeID(), volumes[1].VolumeID())
	}
	volumes[0] = MountedVolumeEvidence{}
	second, err := set.Observe()
	if err != nil || second.Generation() != first.Generation() || second.Fingerprint() != first.Fingerprint() ||
		second.Volumes()[0].VolumeID() != "alpha" {
		t.Fatalf("stable read-only observation changed or exposed set storage: generation=%d err=%v", second.Generation(), err)
	}

	beta.mu.Lock()
	beta.generation++
	beta.mu.Unlock()
	third, err := set.Observe()
	if err != nil || third.Generation() != second.Generation()+1 || third.Fingerprint() == second.Fingerprint() {
		t.Fatalf("member-owner change did not advance aggregate freshness: before=%d after=%d err=%v",
			second.Generation(), third.Generation(), err)
	}
	if _, err := json.Marshal(third); err == nil {
		t.Fatal("complete mounted-set evidence must remain non-serializable")
	}
	var decoded MountedVolumeSetEvidence
	if err := json.Unmarshal([]byte(`{"complete":true,"generation":3}`), &decoded); err == nil {
		t.Fatal("complete mounted-set evidence must not be deserializable")
	}
}

func TestMountedVolumeSetLeaseRetainsAllOwnersUntilClosed(t *testing.T) {
	alpha, _ := mountedOwnerFixtureForSet(t, "alpha", "/srv/phantowd/volumes/alpha",
		"11111111-2222-3333-4444-555555555555", 101, 102, 17)
	beta, _ := mountedOwnerFixtureForSet(t, "beta", "/srv/phantowd/volumes/beta",
		"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", 201, 202, 33)
	set, err := newMountedVolumeSet([]string{"beta", "alpha"}, []*Owner{beta, alpha})
	if err != nil {
		t.Fatal("create fixed mounted-volume roster:", err)
	}

	lease, evidence, err := set.Acquire(context.Background())
	if err != nil || lease == nil || !evidence.Complete() || evidence.Generation() != 1 || len(evidence.Volumes()) != 2 {
		t.Fatalf("acquire complete fixed-roster lease: lease=%v evidence=%+v err=%v", lease != nil, evidence, err)
	}
	if got := evidence.Volumes(); got[0].VolumeID() != "alpha" || got[1].VolumeID() != "beta" {
		t.Fatalf("lease evidence is not in canonical order: %q, %q", got[0].VolumeID(), got[1].VolumeID())
	}
	opened, err := lease.OpenDirectory("alpha", ".")
	if err != nil {
		t.Fatal("open through the matching volume lease:", err)
	}
	if _, err := lease.OpenDirectory("unknown", "."); !errors.Is(err, ErrInvalid) {
		t.Fatalf("set lease opened an unrostered volume: %v", err)
	}

	for _, owner := range []*Owner{alpha, beta} {
		if err := owner.Drain(); !errors.Is(err, ErrBusy) || owner.State() != StateDraining {
			t.Fatalf("active set lease did not block drain for %q: state=%s err=%v", owner.target, owner.State(), err)
		}
	}
	if _, err := lease.OpenDirectory("alpha", "."); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("draining volume still admitted directory access: %v", err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal("close every volume lease:", err)
	}
	if _, err := opened.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("set lease close did not close its tracked directory descriptor: %v", err)
	}
	if err := lease.Close(); err != nil {
		t.Fatalf("repeated set lease close was not idempotent: %v", err)
	}
	for _, owner := range []*Owner{alpha, beta} {
		if err := owner.Unmount(context.Background()); err != nil {
			t.Fatalf("unmount %q after the all-volume lease closed: %v", owner.target, err)
		}
	}
}

func TestMountedVolumeSetLeaseRollsBackIfMemberChangesDuringAcquire(t *testing.T) {
	alpha, _ := mountedOwnerFixtureForSet(t, "alpha", "/srv/phantowd/volumes/alpha",
		"11111111-2222-3333-4444-555555555555", 101, 102, 17)
	beta, betaInspector := mountedOwnerFixtureForSet(t, "beta", "/srv/phantowd/volumes/beta",
		"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", 201, 202, 33)
	set, err := newMountedVolumeSet([]string{"alpha", "beta"}, []*Owner{alpha, beta})
	if err != nil {
		t.Fatal("create fixed mounted-volume roster:", err)
	}
	observations := 0
	betaInspector.observeHook = func(observedPath string) {
		if observedPath == beta.target {
			observations++
			if observations == 2 {
				betaInspector.observeError = true
			}
		}
	}
	if lease, evidence, err := set.Acquire(context.Background()); !errors.Is(err, ErrReview) || lease != nil || evidence.Complete() {
		t.Fatalf("changed member returned partial group authority: lease=%v evidence=%+v err=%v", lease != nil, evidence, err)
	}
	if err := alpha.Drain(); err != nil {
		t.Fatalf("failed acquisition leaked the earlier member's lease: %v", err)
	}
	if beta.State() != StateReviewRequired {
		t.Fatalf("changed member was not quarantined: state=%s", beta.State())
	}
	if err := alpha.Unmount(context.Background()); err != nil {
		t.Fatal("unmount first member after atomic rollback:", err)
	}
}

func TestMountedVolumeSetLeaseRevokesOnlyTheChangedVolume(t *testing.T) {
	alpha, _ := mountedOwnerFixtureForSet(t, "alpha", "/srv/phantowd/volumes/alpha",
		"11111111-2222-3333-4444-555555555555", 101, 102, 17)
	beta, betaInspector := mountedOwnerFixtureForSet(t, "beta", "/srv/phantowd/volumes/beta",
		"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", 201, 202, 33)
	set, err := newMountedVolumeSet([]string{"alpha", "beta"}, []*Owner{alpha, beta})
	if err != nil {
		t.Fatal("create fixed mounted-volume roster:", err)
	}
	lease, evidence, err := set.Acquire(context.Background())
	if err != nil || lease == nil || !evidence.Complete() {
		t.Fatalf("acquire complete mounted-volume roster: lease=%v complete=%v err=%v", lease != nil, evidence.Complete(), err)
	}
	alphaHandle, err := lease.OpenDirectory("alpha", ".")
	if err != nil {
		t.Fatal("open independent alpha volume:", err)
	}
	betaHandle, err := lease.OpenDirectory("beta", ".")
	if err != nil {
		t.Fatal("open beta volume before identity loss:", err)
	}

	betaInspector.observeError = true
	if _, err := lease.OpenDirectory("beta", "."); !errors.Is(err, ErrReview) {
		t.Fatalf("changed beta volume did not fail closed: %v", err)
	}
	if beta.State() != StateReviewRequired {
		t.Fatalf("changed beta Owner was not quarantined: %s", beta.State())
	}
	if _, err := betaHandle.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("beta identity failure did not revoke beta's tracked descriptor: %v", err)
	}
	if _, err := alphaHandle.Stat(); err != nil {
		t.Fatalf("beta identity failure revoked an unrelated alpha descriptor: %v", err)
	}
	if _, err := lease.OpenDirectory("alpha", "."); err != nil {
		t.Fatalf("beta identity failure blocked independent alpha access: %v", err)
	}
	alphaIndependentLease, err := alpha.Acquire(context.Background())
	if err != nil {
		t.Fatalf("beta identity failure blocked an independent alpha lease: %v", err)
	}
	if _, err := alphaIndependentLease.OpenDirectory("."); err != nil {
		_ = alphaIndependentLease.Close()
		t.Fatalf("independent alpha lease could not open its qualified root: %v", err)
	}
	if err := alphaIndependentLease.Close(); err != nil {
		t.Fatalf("close independent alpha lease after beta quarantine: %v", err)
	}

	// Restoring the observer models the anchor returning. The old Owner and
	// child lease must remain quarantined; recovery needs fresh qualification.
	betaInspector.observeError = false
	if _, err := lease.OpenDirectory("beta", "."); !errors.Is(err, ErrReview) {
		t.Fatalf("returned beta anchor revived its old child lease: %v", err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal("close group lease after member quarantine:", err)
	}
	if err := alpha.Drain(); err != nil {
		t.Fatalf("release independent alpha after group close: %v", err)
	}
	if err := alpha.Unmount(context.Background()); err != nil {
		t.Fatal("unmount independent alpha after group close:", err)
	}
}

func TestMountedVolumeSetWithEvidenceKeepsRosterLockedDuringInspection(t *testing.T) {
	alpha, _ := mountedOwnerFixtureForSet(t, "alpha", "/srv/phantowd/volumes/alpha",
		"11111111-2222-3333-4444-555555555555", 101, 102, 17)
	beta, _ := mountedOwnerFixtureForSet(t, "beta", "/srv/phantowd/volumes/beta",
		"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", 201, 202, 33)
	set, err := newMountedVolumeSet([]string{"alpha", "beta"}, []*Owner{alpha, beta})
	if err != nil {
		t.Fatal("create fixed mounted-volume roster:", err)
	}
	called := false
	err = set.WithEvidence(func(evidence MountedVolumeSetEvidence) error {
		called = true
		if !evidence.Complete() || evidence.Generation() != 1 || len(evidence.Volumes()) != 2 {
			return errors.New("inspection received incomplete fixed-roster evidence")
		}
		if set.mu.TryLock() {
			set.mu.Unlock()
			return errors.New("inspection did not retain the roster lock")
		}
		for _, owner := range []*Owner{alpha, beta} {
			if owner.mu.TryLock() {
				owner.mu.Unlock()
				return errors.New("inspection did not retain every member Owner lock")
			}
		}
		return nil
	})
	if err != nil || !called {
		t.Fatalf("fixed-roster inspection did not run under all locks: called=%v err=%v", called, err)
	}
	if !alpha.mu.TryLock() {
		t.Fatal("member Owner lock remained held after inspection")
	}
	alpha.mu.Unlock()
}

func TestMountedVolumeSetRejectsIncompleteOrAmbiguousRoster(t *testing.T) {
	alpha, _ := mountedOwnerFixtureForSet(t, "alpha", "/srv/phantowd/volumes/alpha",
		"11111111-2222-3333-4444-555555555555", 101, 102, 17)
	beta, _ := mountedOwnerFixtureForSet(t, "beta", "/srv/phantowd/volumes/beta",
		"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", 201, 202, 33)
	if _, err := newMountedVolumeSet([]string{"alpha", "beta"}, []*Owner{alpha}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("incomplete roster was accepted: %v", err)
	}
	if _, err := newMountedVolumeSet([]string{"alpha", "alpha"}, []*Owner{alpha, beta}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("duplicate logical IDs were accepted: %v", err)
	}

	ambiguous, _ := mountedOwnerFixtureForSet(t, "gamma", "/srv/phantowd/volumes/gamma",
		"99999999-2222-3333-4444-555555555555", 301, 302, 17)
	set, err := newMountedVolumeSet([]string{"alpha", "gamma"}, []*Owner{alpha, ambiguous})
	if err != nil {
		t.Fatal("create ambiguous-identity fixture roster:", err)
	}
	if evidence, err := set.Observe(); !errors.Is(err, ErrReview) || evidence.Complete() || evidence.Volumes() != nil {
		t.Fatalf("duplicate block-device identity yielded a partial/complete set: evidence=%+v err=%v", evidence, err)
	}
}

func TestMountedVolumeSetLocksAllOwnersBeforeReadingAny(t *testing.T) {
	alpha, alphaInspector := mountedOwnerFixtureForSet(t, "alpha", "/srv/phantowd/volumes/alpha",
		"11111111-2222-3333-4444-555555555555", 101, 102, 17)
	beta, _ := mountedOwnerFixtureForSet(t, "beta", "/srv/phantowd/volumes/beta",
		"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", 201, 202, 33)
	set, err := newMountedVolumeSet([]string{"alpha", "beta"}, []*Owner{alpha, beta})
	if err != nil {
		t.Fatal("create fixed mounted-volume roster:", err)
	}
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	releaseClosed := false
	releaseObserver := func() {
		if !releaseClosed {
			close(release)
			releaseClosed = true
		}
	}
	defer releaseObserver()
	alphaInspector.observeHook = func(observedPath string) {
		if observedPath == alpha.target {
			select {
			case entered <- struct{}{}:
			default:
			}
			<-release
		}
	}
	result := make(chan error, 1)
	go func() {
		_, err := set.Observe()
		result <- err
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		releaseObserver()
		t.Fatal("snapshot did not reach first owner observation")
	}
	if beta.mu.TryLock() {
		beta.mu.Unlock()
		releaseObserver()
		t.Fatal("later Owner was not held locked while the first Owner was being observed")
	}
	releaseObserver()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal("complete locked observation failed:", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("snapshot did not finish after releasing the fixture observer")
	}
}

func TestObserveMountedVolumeReturnsFreshNonSerializableEvidence(t *testing.T) {
	owner, qualification, driver, _, _ := mountOwnerFixture(t)
	if _, err := owner.ObserveMountedVolume(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unmounted owner returned storage evidence: %v", err)
	}
	if err := owner.Qualify(qualification); err != nil {
		t.Fatal("qualify fixture mount:", err)
	}
	if err := owner.Mount(context.Background()); err != nil {
		t.Fatal("mount fixture:", err)
	}

	evidence, err := owner.ObserveMountedVolume()
	if err != nil {
		t.Fatal("observe verified mount:", err)
	}
	if evidence.VolumeID() != "fixture-volume" || evidence.FilesystemUUID() != "11111111-2222-3333-4444-555555555555" ||
		evidence.MountPath() != "/fixture/target" || evidence.Compatibility() != qualifiedCompatibility ||
		evidence.Generation() != 1 || evidence.MountID() != 102 || evidence.DeviceMajor() != 8 ||
		evidence.DeviceMinor() != 17 || evidence.ReadOnly() {
		t.Fatalf("mounted evidence did not capture the verified Owner tuple: %+v", evidence)
	}
	if _, err := json.Marshal(evidence); err == nil {
		t.Fatal("transient mount evidence must not be serializable")
	}
	var decoded MountedVolumeEvidence
	if err := json.Unmarshal([]byte(`{"volume_id":"fixture-volume"}`), &decoded); err == nil {
		t.Fatal("transient mount evidence must not be deserializable")
	}

	owner.root.(*modeledRoot).invalid = true
	if _, err := owner.ObserveMountedVolume(); !errors.Is(err, ErrReview) || owner.State() != StateReviewRequired {
		t.Fatalf("mount replacement did not invalidate observation and quarantine Owner: state=%s err=%v", owner.State(), err)
	}
	if driver.mountCalls != 1 || driver.unmountCalls != 0 {
		t.Fatalf("evidence observation retried or cleaned up a mount: mount=%d unmount=%d", driver.mountCalls, driver.unmountCalls)
	}
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
