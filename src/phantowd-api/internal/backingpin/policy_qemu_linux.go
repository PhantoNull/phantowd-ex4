//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package backingpin

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsipolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicystore"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/nfsconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
	"golang.org/x/sys/unix"
)

// Generated fixture only. The disabled target deliberately grants NO startup
// authority; this policy names the separately authorized static FD test child.
func fixtureBackingPolicy(revision uint64, relative string) naspolicy.Config {
	shares := shareconfig.Config{Format: shareconfig.Format, SchemaVersion: 1, Revision: revision,
		Volumes: []shareconfig.Volume{{ID: "qemu-plan", FilesystemUUID: "11111111-2222-3333-4444-555555555555"}},
		Users:   []shareconfig.User{}, Shares: []shareconfig.Share{}}
	return naspolicy.Config{Format: naspolicy.Format, SchemaVersion: 1, Revision: revision,
		FileServices: fileservice.Config{Format: fileservice.ConfigFormat, SchemaVersion: 1, Revision: revision, Shares: shares,
			NFS: nfsconfig.Policy{Format: nfsconfig.Format, SchemaVersion: 1, Revision: revision, VolumeRevision: revision, Exports: []nfsconfig.Export{}}},
		ISCSI: iscsipolicy.Policy{Format: iscsipolicy.Format, SchemaVersion: 1, Revision: revision, VolumeRevision: revision,
			Backings: []iscsipolicy.Backing{{ID: "fixture-backing", VolumeID: "qemu-plan", RelativePath: relative, CapacityBytes: 4096, BlockSize: 512, Allocation: "preallocated"}},
			Targets: []iscsipolicy.Target{{ID: "fixture-target", Name: "iqn.2001-04.com.example:fixture-target", State: "disabled",
				LUNs: []iscsipolicy.LUN{{ID: "fixture-lun", Number: 0, BackingID: "fixture-backing", Access: "rw"}},
				Initiators: []iscsipolicy.Initiator{{Name: "iqn.2001-04.com.example:fixture-peer",
					Authentication: iscsipolicy.Authentication{Mode: "chap", InitiatorUser: "fixture-peer", InitiatorSecretRef: "fixture-secret"},
					Grants:         []iscsipolicy.Grant{{LUNID: "fixture-lun", Access: "rw"}}}}}}}}
}

func createFixturePolicyOwner(directory, relative string) (*naspolicystore.Owner, error) {
	if err := os.Mkdir(directory, 0700); err != nil {
		return nil, err
	}
	store, err := naspolicystore.Open(directory)
	if err != nil {
		return nil, err
	}
	commitErr := store.Commit(0, fixtureBackingPolicy(1, relative))
	closeErr := store.Close()
	if err := errors.Join(commitErr, closeErr); err != nil {
		return nil, err
	}
	return naspolicystore.OpenOwner(directory)
}

// Existing generated policy only, no symlink/create fallback. Mutation and
// exact restoration deliberately violate the cooperating-writer contract.
func mutateFixturePolicy(directory string) error {
	return mutateFixtureDocument(directory, "nas-services.json")
}

func mutateFixtureDocument(directory, name string) error {
	if name != "nas-services.json" && name != "chap-secrets.json" {
		return ErrInvalid
	}
	name = directory + "/" + name
	original, err := os.ReadFile(name)
	if err != nil {
		return err
	}
	for _, data := range [][]byte{[]byte("{interrupted"), original} {
		fd, err := unix.Open(name, unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		f := os.NewFile(uintptr(fd), "generated-policy-mutation")
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&07777 != 0600 || st.Nlink != 1 || st.Uid != uint32(os.Geteuid()) {
			f.Close()
			return errors.New("unsafe fixture policy mutation")
		}
		if err := f.Truncate(0); err != nil {
			f.Close()
			return err
		}
		n, writeErr := f.Write(data)
		if n != len(data) && writeErr == nil {
			writeErr = errors.New("short policy mutation")
		}
		if err := errors.Join(writeErr, f.Sync(), f.Close()); err != nil {
			return err
		}
	}
	return nil
}

func exercisePolicyWritableFixture(ctx context.Context, owner *writableOwner, backend *fixtureWritableBackend, source *naspolicystore.Owner, directory, relative, kind string, mountLease *mountowner.MountedVolumeSetLease) error {
	if owner.policy == nil {
		return errors.New("policy not retained by consumer")
	}
	if !errors.Is(source.Commit(ctx, 1, fixtureBackingPolicy(2, relative)), naspolicystore.ErrBusy) || !errors.Is(source.Close(), naspolicystore.ErrBusy) {
		return errors.New("consumer did not privately fence desired writer")
	}
	if err := owner.start(ctx); err != nil {
		return err
	}
	if err := owner.observe(ctx); err != nil {
		return err
	}
	if kind == "policy-normal" {
		if err := owner.stop(ctx); err != nil {
			return err
		}
		if !owner.released || owner.policy != nil || !backend.stopWithLiveReference || backend.stopCalls != 1 {
			return errors.New("policy release preceded verified stop")
		}
		select {
		case <-backend.done:
		default:
			return errors.New("policy release before actual child reap")
		}
		if err := source.Commit(ctx, 1, fixtureBackingPolicy(2, relative)); err != nil {
			return err
		}
		return nil
	}
	backend.stopFailure = kind == "policy-uncertain"
	if err := mutateFixturePolicy(directory); err != nil {
		return err
	}
	if err := owner.observe(ctx); !errors.Is(err, ErrReview) {
		return errors.New("policy mutation did not stop consumer")
	}
	if backend.stopCalls != 1 || !backend.stopWithLiveReference {
		return errors.New("policy loss stop ordering")
	}
	if backend.stopFailure {
		if owner.released || owner.policy == nil || owner.file == nil || owner.pin.consumer != owner {
			return errors.New("uncertain stop dropped combined claims")
		}
		if !errors.Is(source.Close(), naspolicystore.ErrBusy) || !errors.Is(mountLease.Close(), mountowner.ErrBusy) {
			return errors.New("uncertainty released policy/mount")
		}
		if live, err := backend.running(ctx); err != nil || !live {
			return errors.New("uncertain policy fixture must keep actual child alive")
		}
		if _, err := owner.file.Stat(); err != nil {
			return err
		}
	} else {
		if !owner.released || owner.policy != nil || owner.file != nil {
			return errors.New("confirmed stop did not release combined claims")
		}
		select {
		case <-backend.done:
		default:
			return errors.New("policy drift release before reap")
		}
	}
	for _, op := range []func() error{func() error { return owner.start(ctx) }, func() error { return owner.observe(ctx) }, func() error { return owner.stop(ctx) }, owner.close} {
		if !errors.Is(op(), ErrReview) {
			return errors.New("restored policy revived consumer")
		}
	}
	if backend.stopCalls != 1 {
		return errors.New("restored policy retried stop")
	}
	if !errors.Is(source.Commit(ctx, 1, fixtureBackingPolicy(2, relative)), naspolicystore.ErrReview) {
		return errors.New("restored source regained writer")
	}
	return nil
}

func emitPolicyWritableMarker() {
	fmt.Println("PHANTOWD_POLICY_BACKING_LIFETIME_READY private_revision_claim=true exact_backing_selection=true real_mount_owner=true consumer_uid=1000 stop_before_policy_release=true uncertain_stop_retains_policy_mount_rw=true restored_policy_no_revival=true no_retry=true product_activation=false scope=disposable-qemu-only")
}
