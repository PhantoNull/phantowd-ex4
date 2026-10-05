//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package backingpin

import (
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
	for _, kind := range []string{"normal", "replace-second", "uncertain"} {
		if err := targetWritableCase(set, workspace, kind); err != nil {
			return fmt.Errorf("target roster fixture %s: %w", kind, err)
		}
	}
	fmt.Println("PHANTOWD_TARGET_BACKING_LIFETIME_READY complete_roster=true canonical_lun_order=true members=2 block_sizes=512,4096 actual_mount_owner=true consumer_uid=1000 admission_rollback=true stop_once_before_all_release=true second_member_drift=true uncertain_retains_all_sources=true no_retry=true target_activation=false scope=disposable-qemu-only")
	return nil
}
func targetWritableCase(set *mountowner.MountedVolumeSet, workspace, kind string) (result error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
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
	commitErr := store.Commit(0, fixtureTargetPolicy(1, relative[0], relative[1]))
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
	if kind == "normal" {
		if owner, err := newTargetWritableOwner(ctx, inputs[:1], &fixtureTargetBackend{}, policy, 1, secrets, 1, "fixture-target"); owner != nil || !errors.Is(err, ErrInvalid) {
			return errors.New("partial target admitted")
		}
		fd, err := unix.Open(paths[1], unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		if err != nil {
			return err
		}
		ro := os.NewFile(uintptr(fd), "refused-target-member")
		bad := append([]targetSelection(nil), inputs...)
		bad[1].file = ro
		owner, admitErr := newTargetWritableOwner(ctx, bad, &fixtureTargetBackend{}, policy, 1, secrets, 1, "fixture-target")
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
	owner, err := newTargetWritableOwner(ctx, inputs, backend, policy, 1, secrets, 1, "fixture-target")
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
		if owner.policy != nil {
			result = errors.Join(result, owner.policy.Release())
		}
		if owner.credentials != nil {
			result = errors.Join(result, owner.credentials.Release())
		}
	}()
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
