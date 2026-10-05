//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package backingpin

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsicredentials"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsipolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicystore"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/nfsconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
	"golang.org/x/sys/unix"
)

const targetFixtureFirst = "PHANTOWD_TARGET_ZERO"
const targetFixtureSecond = "PHANTOWD_TARGET_SEVEN"

func fixtureTargetPolicy(revision uint64, first, second string) naspolicy.Config {
	p := fixtureBackingPolicy(revision, first)
	p.ISCSI.Backings = append(p.ISCSI.Backings, iscsipolicy.Backing{ID: "fixture-second", VolumeID: "qemu-plan", RelativePath: second, CapacityBytes: 8192, BlockSize: 4096, Allocation: "preallocated"})
	p.ISCSI.Targets[0].LUNs = append(p.ISCSI.Targets[0].LUNs, iscsipolicy.LUN{ID: "fixture-second-lun", Number: 7, BackingID: "fixture-second", Access: "rw"})
	p.ISCSI.Targets[0].Initiators[0].Grants = append(p.ISCSI.Targets[0].Initiators[0].Grants, iscsipolicy.Grant{LUNID: "fixture-second-lun", Access: "rw"})
	return p
}

type fixtureTargetBackend struct {
	fixtureWritableBackend
	members       []targetBacking
	allLiveAtStop bool
}

func (b *fixtureTargetBackend) startTarget(ctx context.Context, members []targetBacking) error {
	if len(members) != 2 || members[0].number != 0 || members[1].number != 7 || members[0].capacity != 4096 || members[1].capacity != 8192 ||
		members[0].blockSize != 512 || members[1].blockSize != 4096 || members[0].access != "rw" || members[1].access != "rw" {
		return ErrInvalid
	}
	b.members = append([]targetBacking(nil), members...)
	return b.startFixedConsumer(ctx, []*os.File{members[0].file, members[1].file}, "-qemu-target-backing-consumer", []string{targetFixtureFirst, targetFixtureSecond})
}
func (b *fixtureTargetBackend) stop(ctx context.Context) error {
	b.allLiveAtStop = true
	for _, member := range b.members {
		if _, err := member.file.Stat(); err != nil {
			b.allLiveAtStop = false
		}
	}
	return b.fixtureWritableBackend.stop(ctx)
}

func runTargetWritableFixtures(set *mountowner.MountedVolumeSet, workspace string) error {
	for _, kind := range []string{"normal", "replace-second", "uncertain", "configured-smb", "configured-nfs", "duplicate-open", "later-held", "concurrent-open", "close-uncertain", "capacity-bound"} {
		if err := targetWritableCase(set, workspace, kind); err != nil {
			return fmt.Errorf("target roster fixture %s: %w", kind, err)
		}
	}
	fmt.Println("PHANTOWD_TARGET_BACKING_LIFETIME_READY complete_roster=true canonical_lun_order=true members=2 block_sizes=512,4096 actual_mount_owner=true consumer_uid=1000 admission_rollback=true stop_once_before_all_release=true second_member_drift=true uncertain_retains_all_sources=true no_retry=true target_activation=false scope=disposable-qemu-only")
	fmt.Println("PHANTOWD_TARGET_KNOWN_USE_READY coherent_policy=true smb_exposure_refused=true nfs_exposure_refused=true readonly_refused=true later_member=true caller_resources_preserved=true no_source_claims=true no_backend_effects=true global_use=false activation=false scope=disposable-qemu-only")
	fmt.Println("PHANTOWD_TARGET_OBJECT_USE_READY shared_authority=true independent_opens_refused=true later_conflict_atomic=true singleton_same_authority=true actual_mount_owner=true caller_resources_preserved=true uncertain_retains_reservation=true no_retry=true cooperative=true external_exclusion=false global_use=false activation=false scope=disposable-qemu-only")
	fmt.Println("PHANTOWD_TARGET_OBJECT_CONCURRENCY_READY independent_opens=true simultaneous_admission=true joined_before_release=true exactly_one_winner=true rejected_callers_preserved=true busy_until_stop=true actual_child_reaped=true verified_reuse=true actual_mount_owner=true cooperative=true external_exclusion=false activation=false scope=disposable-qemu-only")
	fmt.Println("PHANTOWD_TARGET_OBJECT_CLOSE_READY actual_later_fd_close_failure=true earlier_fd_closed=true all_metadata_retained=true whole_reservation_retained=true independent_open_refused=true policy_credentials_mount_retained=true terminal_review=true no_close_retry=true actual_mount_owner=true activation=false scope=disposable-qemu-only")
	fmt.Println("PHANTOWD_TARGET_OBJECT_CAPACITY_READY actual_objects=64 whole_overflow_atomic=true rejected_callers_preserved=true unused_slot_reusable=true released_capacity_reusable=true actual_mount_owner=true no_backend_effects=true cooperative=true activation=false scope=disposable-qemu-only")
	return nil
}
func targetWritableCase(set *mountowner.MountedVolumeSet, workspace, kind string) (result error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	uses := newBackingUseOwner()
	defer func() { result = errors.Join(result, uses.close()) }()
	dir := workspace + "/target-" + kind
	if err := os.Mkdir(dir, 0700); err != nil {
		return err
	}
	lease, _, err := set.Acquire(ctx)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, lease.Close()) }()
	paths := []string{dir + "/first", dir + "/second"}
	relative := []string{filepath.Base(workspace) + "/target-" + kind + "/first", filepath.Base(workspace) + "/target-" + kind + "/second"}
	if kind == "configured-smb" || kind == "configured-nfs" {
		if err := os.Mkdir(dir+"/exposed", 0700); err != nil {
			return err
		}
		paths[1] = dir + "/exposed/second"
		relative[1] = filepath.Base(workspace) + "/target-" + kind + "/exposed/second"
	}
	for i, path := range paths {
		if err := os.WriteFile(path, make([]byte, 4096*(i+1)), 0600); err != nil {
			return err
		}
	}
	if err := os.Mkdir(dir+"/policy", 0700); err != nil {
		return err
	}
	store, err := naspolicystore.Open(dir + "/policy")
	if err != nil {
		return err
	}
	p := fixtureTargetPolicy(1, relative[0], relative[1])
	if kind == "configured-smb" || kind == "configured-nfs" {
		fixtureTargetExposure(&p, kind, filepath.Dir(relative[1])) // Conflict in LATER LUN only.
		if p.Validate() != nil || !knownBackingPathIsolated(p, p.ISCSI.Backings[0]) || knownBackingPathIsolated(p, p.ISCSI.Backings[1]) {
			return ErrReview
		}
	}
	commitErr := store.Commit(0, p)
	if err := errors.Join(commitErr, store.Close()); err != nil {
		return err
	}
	policy, err := naspolicystore.OpenOwner(dir + "/policy")
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, policy.Close()) }()
	secrets, err := iscsicredentials.OpenQEMUFixture(dir + "/secrets")
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, secrets.Close()) }()
	var inputs []targetSelection
	for i, path := range paths {
		pin, _, err := OpenFromMountedLease(lease, "qemu-plan", relative[i], uint64(4096*(i+1)))
		if err != nil {
			return err
		}
		defer func() { result = errors.Join(result, pin.Close()) }()
		fd, err := unix.Open(path, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		if err != nil {
			return err
		}
		file := os.NewFile(uintptr(fd), "synthetic-target-member")
		defer func() { // Independent fixture disposal, only for still-open handles.
			if _, err := file.Stat(); err == nil {
				result = errors.Join(result, file.Close())
			}
		}()
		id := iscsipolicy.BackingID("fixture-backing")
		if i == 1 {
			id = "fixture-second"
		}
		inputs = append(inputs, targetSelection{backingID: id, pin: pin, file: file})
	}
	if kind == "configured-smb" || kind == "configured-nfs" {
		backend := &fixtureTargetBackend{}
		owner, err := newTargetWritableOwner(ctx, inputs, backend, policy, 1, secrets, 1, "fixture-target", uses)
		if owner != nil || !errors.Is(err, ErrInvalid) || backend.prepareCalls != 0 || backend.cmd != nil || backend.stopCalls != 0 {
			return ErrReview
		}
		if target, defs, err := lioTargetDefinition(p, "fixture-target"); target.ID != "" || defs != nil || !errors.Is(err, ErrInvalid) {
			return ErrReview
		}
		// Neither older singleton policy/credential composition may bypass this
		// prerequisite. No backend preparation/execution or caller transfer occurs.
		single := &fixtureWritableBackend{}
		second := inputs[1]
		if owner, err := newPolicyBoundWritableOwner(ctx, second.pin, second.file, single, policy, 1, second.backingID, uses); owner != nil || !errors.Is(err, ErrInvalid) {
			return ErrReview
		}
		if owner, err := newCredentialBoundWritableOwner(ctx, second.pin, second.file, single, policy, 1, second.backingID, secrets, 1, "fixture-target", uses); owner != nil || !errors.Is(err, ErrInvalid) {
			return ErrReview
		}
		if single.prepareCalls != 0 || single.cmd != nil || single.stopCalls != 0 {
			return ErrReview
		}
		for i, input := range inputs {
			if input.pin.consumer != nil {
				return ErrReview
			}
			if _, err := input.pin.Verify(); err != nil {
				return ErrReview
			}
			if _, err := input.file.Stat(); err != nil {
				return ErrReview
			}
			data, err := os.ReadFile(paths[i])
			if err != nil || !bytes.Equal(data, make([]byte, 4096*(i+1))) {
				return ErrReview
			}
		}
		// Successful direct Close proves no hidden policy/credential claim remains.
		return errors.Join(policy.Close(), secrets.Close())
	}
	if kind == "concurrent-open" {
		return targetConcurrentOpenCase(ctx, lease, paths, relative, inputs, policy, secrets, uses)
	}
	if kind == "close-uncertain" {
		return targetUncertainCloseCase(ctx, lease, paths[0], relative[0], inputs, policy, secrets, uses)
	}
	if kind == "capacity-bound" {
		return targetUseCapacityCase(ctx, lease, dir, paths, relative, inputs, policy, secrets, uses)
	}
	if kind == "later-held" {
		// Only the later member is held through a separate singleton admission.
		// Refusing the complete target must not publish a first-member prefix.
		pin, _, err := OpenFromMountedLease(lease, "qemu-plan", relative[1], 8192)
		if err != nil {
			return err
		}
		defer func() { result = errors.Join(result, pin.Close()) }()
		fd, err := unix.Open(paths[1], unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		if err != nil {
			return err
		}
		file := os.NewFile(uintptr(fd), "later-held-member")
		defer func() {
			if _, err := file.Stat(); err == nil {
				result = errors.Join(result, file.Close())
			}
		}()
		holder, err := newWritableOwner(pin, file, &fixtureWritableBackend{}, uses)
		if err != nil {
			return err
		}
		defer func() { result = errors.Join(result, holder.close()) }()
		backend := &fixtureTargetBackend{}
		target, err := newTargetWritableOwner(ctx, inputs, backend, policy, 1, secrets, 1, "fixture-target", uses)
		if target != nil {
			if err := target.close(); err != nil {
				return err
			}
			return errors.New("later held object admitted")
		}
		if !errors.Is(err, ErrBusy) || backend.prepareCalls != 0 || backend.cmd != nil || backend.stopCalls != 0 {
			return errors.New("later object conflict had backend effects")
		}
		for _, input := range inputs {
			if input.pin.consumer != nil {
				return ErrReview
			}
			if _, err := input.file.Stat(); err != nil {
				return ErrReview
			}
		}
		first, err := newWritableOwner(inputs[0].pin, inputs[0].file, &fixtureWritableBackend{}, uses)
		if err != nil {
			return errors.New("later conflict published an earlier reservation")
		}
		if err := first.close(); err != nil {
			return err
		}
		if err := holder.close(); err != nil {
			return err
		}
		return errors.Join(policy.Close(), secrets.Close())
	}
	if kind == "normal" {
		if owner, err := newTargetWritableOwner(ctx, inputs[:1], &fixtureTargetBackend{}, policy, 1, secrets, 1, "fixture-target", uses); owner != nil || !errors.Is(err, ErrInvalid) {
			return errors.New("partial target admitted")
		}
		fd, err := unix.Open(paths[1], unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		if err != nil {
			return err
		}
		ro := os.NewFile(uintptr(fd), "refused-target-member")
		bad := append([]targetSelection(nil), inputs...)
		bad[1].file = ro
		owner, admitErr := newTargetWritableOwner(ctx, bad, &fixtureTargetBackend{}, policy, 1, secrets, 1, "fixture-target", uses)
		if owner != nil || !errors.Is(admitErr, ErrUnavailable) {
			_ = ro.Close()
			return errors.New("unsafe later descriptor admitted")
		}
		if _, err := ro.Stat(); err != nil {
			return errors.New("failed admission consumed descriptor")
		}
		if err := ro.Close(); err != nil {
			return err
		}
		for _, input := range inputs {
			if input.pin.consumer != nil {
				return errors.New("failed admission retained provisional pin")
			}
			if _, err := input.file.Stat(); err != nil {
				return err
			}
		}
		// Actual Close proves failed admission left no hidden source claims.
		if err := errors.Join(policy.Close(), secrets.Close()); err != nil {
			return err
		}
		policy, err = naspolicystore.OpenOwner(dir + "/policy")
		if err != nil {
			return err
		}
		secrets, err = iscsicredentials.Open(dir + "/secrets")
		if err != nil {
			return err
		}
	}
	// Reverse caller order; the backend must still receive explicit LUN0/7 order.
	inputs[0], inputs[1] = inputs[1], inputs[0]
	backend := &fixtureTargetBackend{}
	owner, err := newTargetWritableOwner(ctx, inputs, backend, policy, 1, secrets, 1, "fixture-target", uses)
	if err != nil {
		return err
	}
	defer func() {
		if owner.released {
			return
		}
		// Independent disposable teardown after assertions; not product recovery.
		if err := backend.teardown(ctx); err != nil {
			result = errors.Join(result, err)
			return
		}
		for i := range owner.group {
			member := &owner.group[i]
			if member.file != nil {
				if err := member.file.Close(); err != nil {
					result = errors.Join(result, err)
					return
				}
				member.file = nil
			}
		}
		for _, member := range owner.group {
			member.pin.mu.Lock()
			member.pin.consumer = nil
			err := member.pin.closeLocked()
			member.pin.mu.Unlock()
			if err != nil {
				result = errors.Join(result, err)
				return
			}
		}
		if err := owner.releaseSourcesLocked(); err != nil {
			result = errors.Join(result, err)
		}
	}()
	if kind == "duplicate-open" {
		// Separate Pins and open file descriptions for the SAME actual objects.
		// This is not a forged inode tuple, repeated pointer or shared FD control.
		var duplicate []targetSelection
		for i, path := range paths {
			pin, _, err := OpenFromMountedLease(lease, "qemu-plan", relative[i], uint64(4096*(i+1)))
			if err != nil {
				return err
			}
			defer func() { result = errors.Join(result, pin.Close()) }()
			fd, err := unix.Open(path, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
			if err != nil {
				return err
			}
			file := os.NewFile(uintptr(fd), "duplicate-target-member")
			defer func() {
				if _, err := file.Stat(); err == nil {
					result = errors.Join(result, file.Close())
				}
			}()
			id := iscsipolicy.BackingID("fixture-backing")
			if i == 1 {
				id = "fixture-second"
			}
			duplicate = append(duplicate, targetSelection{backingID: id, pin: pin, file: file})
		}
		second, admitErr := newTargetWritableOwner(ctx, duplicate, &fixtureTargetBackend{}, policy, 1, secrets, 1, "fixture-target", uses)
		if second != nil {
			// Prepared only: no child/credentials/configfs effects. Independent
			// fixture disposal is needed before reporting the real admission defect.
			if err := second.close(); err != nil {
				return err
			}
			return errors.New("independent owners admitted same backing objects")
		}
		if !errors.Is(admitErr, ErrBusy) {
			return errors.New("duplicate object refusal was not a held-use conflict")
		}
		for _, member := range duplicate {
			if member.pin.consumer != nil {
				return ErrReview
			}
			if _, err := member.file.Stat(); err != nil {
				return ErrReview
			}
		}
		if !errors.Is(uses.close(), ErrBusy) || owner.use.verify() != nil {
			return ErrReview
		}
		return owner.close()
	}
	if !errors.Is(policy.Close(), naspolicystore.ErrBusy) || !errors.Is(secrets.Close(), iscsicredentials.ErrBusy) || !errors.Is(lease.Close(), mountowner.ErrBusy) {
		return errors.New("target did not fence all sources")
	}
	if err := owner.start(ctx); err != nil {
		return err
	}
	if err := owner.observe(ctx); err != nil {
		return err
	}
	for _, member := range owner.group {
		if !errors.Is(member.pin.Close(), ErrBusy) {
			return errors.New("target member close bypass")
		}
	}
	if kind == "replace-second" {
		if err := os.Rename(paths[1], paths[1]+"-old"); err != nil {
			return err
		}
		if err := os.WriteFile(paths[1], make([]byte, 8192), 0600); err != nil {
			return err
		}
		if !errors.Is(owner.observe(ctx), ErrReview) {
			return errors.New("later target member drift accepted")
		}
		replacement, err := os.ReadFile(paths[1])
		if err != nil {
			return err
		}
		for _, value := range replacement {
			if value != 0 {
				return errors.New("target reopened/wrote replacement member")
			}
		}
	} else {
		backend.stopFailure = kind == "uncertain"
		err := owner.stop(ctx)
		if kind == "normal" && err != nil {
			return err
		}
		if kind == "uncertain" && !errors.Is(err, ErrReview) {
			return errors.New("uncertain target stop accepted")
		}
	}
	if backend.stopCalls != 1 || !backend.allLiveAtStop || !backend.stopWithLiveCredentials {
		return errors.New("whole backend stop ordering")
	}
	if kind == "uncertain" {
		if owner.use == nil || owner.use.verify() != nil || !errors.Is(uses.close(), ErrBusy) {
			return errors.New("uncertainty dropped the whole object reservation")
		}
		if owner.released || owner.policy == nil || owner.credentials == nil {
			return errors.New("uncertainty released global target claims")
		}
		for _, member := range owner.group {
			if member.file == nil || member.pin.consumer != owner {
				return errors.New("uncertainty dropped target member")
			}
			if _, err := member.file.Stat(); err != nil {
				return err
			}
		}
		if _, err := backend.credentialPeers[0].Incoming.WriteTo(io.Discard); err != nil {
			return errors.New("uncertainty wiped global credentials")
		}
		if !errors.Is(policy.Close(), naspolicystore.ErrBusy) || !errors.Is(secrets.Close(), iscsicredentials.ErrBusy) || !errors.Is(lease.Close(), mountowner.ErrBusy) {
			return errors.New("uncertainty released global source fence")
		}
		if live, err := backend.running(ctx); err != nil || !live {
			return errors.New("uncertain target fixture child not live")
		}
	} else {
		if !owner.released || owner.policy != nil || owner.credentials != nil {
			return errors.New("verified target teardown incomplete")
		}
		select {
		case <-backend.done:
		default:
			return errors.New("target release before actual reap")
		}
		for _, member := range owner.group {
			if member.file != nil || !member.pin.closed {
				return errors.New("incomplete member release")
			}
		}
		if _, err := backend.credentialPeers[0].Incoming.WriteTo(io.Discard); !errors.Is(err, iscsicredentials.ErrClosed) {
			return errors.New("global credentials not released")
		}
	}
	if kind != "normal" {
		for _, op := range []func() error{func() error { return owner.start(ctx) }, func() error { return owner.observe(ctx) }, func() error { return owner.stop(ctx) }, owner.close} {
			if !errors.Is(op(), ErrReview) {
				return errors.New("target review bypass/retry")
			}
		}
		if backend.stopCalls != 1 || backend.prepareCalls != 1 {
			return errors.New("target repeated teardown/preparation")
		}
	}
	return nil
}

// Real mounted objects and independent open descriptions, not fabricated statx
// identities. Both admissions finish before the winner may release any claim.
// No LIO/configfs activation: only the existing disposable UID1000 child.
func targetConcurrentOpenCase(ctx context.Context, lease *mountowner.MountedVolumeSetLease, paths, relative []string,
	first []targetSelection, policy *naspolicystore.Owner, secrets *iscsicredentials.Owner, uses *backingUseOwner) (result error) {
	var second []targetSelection
	for i, path := range paths {
		pin, _, err := OpenFromMountedLease(lease, "qemu-plan", relative[i], uint64(4096*(i+1)))
		if err != nil {
			return err
		}
		defer func() { result = errors.Join(result, pin.Close()) }()
		fd, err := unix.Open(path, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		if err != nil {
			return err
		}
		file := os.NewFile(uintptr(fd), "concurrent-target-member")
		defer func() {
			if _, err := file.Stat(); err == nil {
				result = errors.Join(result, file.Close())
			}
		}()
		second = append(second, targetSelection{backingID: first[i].backingID, pin: pin, file: file})
	}
	type admission struct {
		index   int
		owner   *writableOwner
		backend *fixtureTargetBackend
		err     error
	}
	inputs := [][]targetSelection{first, second}
	ready, start, done := make(chan struct{}, 2), make(chan struct{}), make(chan admission, 2)
	for index := range inputs {
		go func() {
			backend := &fixtureTargetBackend{}
			ready <- struct{}{}
			<-start
			owner, err := newTargetWritableOwner(ctx, inputs[index], backend, policy, 1, secrets, 1, "fixture-target", uses)
			done <- admission{index, owner, backend, err}
		}()
	}
	<-ready
	<-ready
	close(start)
	// Join BOTH bounded admissions before examining/closing either Owner.
	admitted := []admission{<-done, <-done}
	defer func() {
		for _, a := range admitted {
			if a.owner == nil || a.owner.released {
				continue
			}
			// Independent test-only disposal after an actual child reap. Never
			// reset review or retry the lifecycle/backend stop operation.
			if err := a.backend.teardown(ctx); err != nil {
				result = errors.Join(result, err)
				continue
			}
			a.owner.mu.Lock()
			result = errors.Join(result, a.owner.releaseLocked())
			a.owner.mu.Unlock()
		}
	}()
	winner, loser := admitted[0], admitted[1]
	if winner.owner == nil {
		winner, loser = loser, winner
	}
	if winner.owner == nil || winner.err != nil || loser.owner != nil || !errors.Is(loser.err, ErrBusy) {
		return errors.New("concurrent actual-object admission did not have exactly one winner")
	}
	if loser.backend.prepareCalls != 0 || loser.backend.cmd != nil || loser.backend.stopCalls != 0 {
		return errors.New("concurrent refused admission had backend effects")
	}
	for _, input := range inputs[loser.index] {
		if input.pin.consumer != nil {
			return errors.New("concurrent refusal retained caller pin")
		}
		if _, err := input.pin.Verify(); err != nil {
			return err
		}
		if _, err := input.file.Stat(); err != nil {
			return err
		}
	}
	if !errors.Is(uses.close(), ErrBusy) {
		return errors.New("concurrent winner did not retain shared authority")
	}
	if err := winner.owner.start(ctx); err != nil {
		return err
	}
	if err := winner.owner.observe(ctx); err != nil {
		return err
	}
	if !errors.Is(uses.close(), ErrBusy) {
		return errors.New("active child lost its object reservation")
	}
	if err := winner.owner.stop(ctx); err != nil {
		return err
	}
	if !winner.owner.released || winner.backend.stopCalls != 1 || !winner.backend.allLiveAtStop {
		return errors.New("concurrent winner released without verified whole stop")
	}
	select {
	case <-winner.backend.done:
	default:
		return errors.New("concurrent winner released before actual child reap")
	}
	for _, member := range winner.owner.group {
		if member.file != nil || !member.pin.closed {
			return errors.New("concurrent winner retained unverified member closure")
		}
	}
	// Clear the old readiness bytes through the losing caller's retained fixture
	// handles; the next child must actually write them again, not inherit a marker.
	for i, input := range inputs[loser.index] {
		if _, err := input.file.WriteAt(make([]byte, 4096*(i+1)), 0); err != nil {
			return err
		}
	}
	// Reuse the losing caller's original live handles, not freshly opened files
	// or a new authority. Only verified whole-stop/closure enables admission.
	backend := &fixtureTargetBackend{}
	owner, err := newTargetWritableOwner(ctx, inputs[loser.index], backend, policy, 1, secrets, 1, "fixture-target", uses)
	if err != nil {
		return fmt.Errorf("verified object reuse: %w", err)
	}
	admitted = append(admitted, admission{loser.index, owner, backend, nil})
	if err := owner.start(ctx); err != nil {
		return err
	}
	if err := owner.observe(ctx); err != nil {
		return err
	}
	if err := owner.stop(ctx); err != nil {
		return err
	}
	if !owner.released || backend.stopCalls != 1 || !backend.allLiveAtStop {
		return errors.New("reused target whole-stop witness missing")
	}
	select {
	case <-backend.done:
	default:
		return errors.New("reused target released before actual child reap")
	}
	for _, member := range owner.group {
		if member.file != nil || !member.pin.closed {
			return errors.New("reused target member closure missing")
		}
	}
	return nil
}

// An actual os.File close failure in the later member, not a mocked close
// result. This fault and its independent disposal exist only in the guest.
func targetUncertainCloseCase(ctx context.Context, lease *mountowner.MountedVolumeSetLease, path, relative string,
	inputs []targetSelection, policy *naspolicystore.Owner, secrets *iscsicredentials.Owner, uses *backingUseOwner) (result error) {
	backend := &fixtureTargetBackend{}
	owner, err := newTargetWritableOwner(ctx, inputs, backend, policy, 1, secrets, 1, "fixture-target", uses)
	if err != nil {
		return err
	}
	defer func() {
		// Prepared only; no child/session/kernel consumer was started. Verify
		// already-closed handles without a second Close. Separately close any
		// still-live fixture handle exactly once before all metadata/sources.
		if owner.started || backend.cmd != nil {
			result = errors.Join(result, ErrReview)
			return
		}
		for i := range owner.group {
			member := &owner.group[i]
			if member.file == nil {
				continue
			}
			_, statErr := member.file.Stat()
			if !errors.Is(statErr, os.ErrClosed) {
				if statErr != nil {
					result = errors.Join(result, statErr)
					return
				}
				if err := member.file.Close(); err != nil {
					result = errors.Join(result, err)
					return
				}
			}
			member.file = nil
		}
		for _, member := range owner.group {
			member.pin.mu.Lock()
			if member.pin.consumer != owner {
				member.pin.mu.Unlock()
				result = errors.Join(result, ErrReview)
				return
			}
			member.pin.consumer = nil
			err := member.pin.closeLocked()
			member.pin.mu.Unlock()
			if err != nil {
				result = errors.Join(result, err)
				return
			}
		}
		result = errors.Join(result, owner.releaseSourcesLocked())
		// The review phase is never reset or admitted as product recovery.
	}()
	if err := inputs[1].file.Close(); err != nil {
		return err
	}
	if !errors.Is(owner.close(), ErrReview) || owner.phase != writableReview || owner.released {
		return errors.New("later actual descriptor close failure did not retain review")
	}
	if owner.group[0].file != nil || owner.group[1].file == nil {
		return errors.New("close failure was not after the earlier data close")
	}
	for _, input := range inputs {
		if _, err := input.file.Stat(); !errors.Is(err, os.ErrClosed) {
			return errors.New("close fault did not establish actual descriptor closure")
		}
		if input.pin.consumer != owner || input.pin.closed {
			return errors.New("close uncertainty released a metadata claim")
		}
	}
	if owner.use.verify() != nil || !errors.Is(uses.close(), ErrBusy) ||
		!errors.Is(policy.Close(), naspolicystore.ErrBusy) || !errors.Is(secrets.Close(), iscsicredentials.ErrBusy) ||
		!errors.Is(lease.Close(), mountowner.ErrBusy) {
		return errors.New("close uncertainty released whole reservation or source claims")
	}
	// Even the EARLIER object's already-closed data FD must not permit a fresh
	// independent singleton to claim it while the whole roster stays in review.
	pin, _, err := OpenFromMountedLease(lease, "qemu-plan", relative, 4096)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, pin.Close()) }()
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), "close-review-independent-member")
	defer func() { result = errors.Join(result, file.Close()) }()
	second, admitErr := newWritableOwner(pin, file, &fixtureWritableBackend{}, uses)
	if second != nil || !errors.Is(admitErr, ErrBusy) || pin.consumer != nil {
		if second != nil {
			_ = second.close()
		}
		return errors.New("close review lost the earlier object's reservation")
	}
	if _, err := file.Stat(); err != nil {
		return err
	}
	for _, operation := range []func() error{owner.close, func() error { return owner.start(ctx) }, func() error { return owner.observe(ctx) }, func() error { return owner.stop(ctx) }} {
		if !errors.Is(operation(), ErrReview) {
			return errors.New("close uncertainty allowed lifecycle retry")
		}
	}
	if backend.prepareCalls != 0 || backend.stopCalls != 0 || backend.cmd != nil || owner.use.verify() != nil {
		return errors.New("close review retried backend or released reservation")
	}
	return nil
}

// Declared synthetic exposure only: no SMB/NFS runtime is activated here.
func fixtureTargetExposure(p *naspolicy.Config, protocol, relative string) {
	if protocol == "configured-smb" {
		p.FileServices.Shares.Users = []shareconfig.User{{ID: "reader", Name: "reader"}}
		p.FileServices.Shares.Shares = []shareconfig.Share{{ID: "visible", Name: "visible", VolumeID: "qemu-plan", RelativePath: relative,
			Grants: []shareconfig.Grant{{UserID: "reader", Access: "ro"}}}}
	} else if protocol == "configured-nfs" {
		p.FileServices.NFS.Exports = []nfsconfig.Export{{ID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", VolumeID: "qemu-plan", RelativePath: relative,
			Clients: []nfsconfig.Client{{Network: "127.0.0.1/32", Access: "ro", Squash: "all", AnonymousUID: 1000, AnonymousGID: 1000, Security: "sys"}}}}
	}
}
