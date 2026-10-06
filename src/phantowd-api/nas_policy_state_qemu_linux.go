//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsipolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicystore"
	"golang.org/x/sys/unix"
)

func qemuPersistentNASPolicy(revision uint64) naspolicy.Config {
	access, relative := "ro", "luns/old.img"
	if revision > 1 {
		access, relative = "rw", "luns/new.img"
	}
	return naspolicy.Config{Format: naspolicy.Format, SchemaVersion: 1, Revision: revision,
		FileServices: qemuPersistentServices(revision),
		ISCSI: iscsipolicy.Policy{Format: iscsipolicy.Format, SchemaVersion: 1, Revision: revision, VolumeRevision: revision,
			Backings: []iscsipolicy.Backing{{ID: "fixture-backing", VolumeID: "fixture-volume", RelativePath: relative,
				CapacityBytes: 4096, BlockSize: 512, Allocation: "preallocated"}},
			Targets: []iscsipolicy.Target{{ID: "fixture-target", Name: "iqn.2001-04.com.example:fixture-target", State: "disabled",
				LUNs: []iscsipolicy.LUN{{ID: "fixture-lun", Number: 0, BackingID: "fixture-backing", Access: access}},
				Initiators: []iscsipolicy.Initiator{{Name: "iqn.2001-04.com.example:fixture-peer",
					Authentication: iscsipolicy.Authentication{Mode: "chap", InitiatorUser: "fixture-peer", InitiatorSecretRef: "fixture-inbound"},
					Grants:         []iscsipolicy.Grant{{LUNID: "fixture-lun", Access: access}}}}}}}}
}

// Guarded generated-disk two-boot harness, also usable with a host TempDir.
// This saves desired references only: no backing, credential or service opens.
func exerciseQEMUNASPolicyPersistence(root, phase string) error {
	dir, corrupt := root+"/nas-policy", root+"/nas-policy-corrupt"
	pending, err := json.Marshal(qemuPersistentNASPolicy(3))
	if err != nil {
		return err
	}
	if phase == "seed" {
		for _, path := range []string{dir, corrupt} {
			if err := os.Mkdir(path, 0700); err != nil {
				return err
			}
		}
		s, err := naspolicystore.Open(dir)
		if err != nil {
			return err
		}
		defer s.Close()
		for revision := uint64(1); revision <= 2; revision++ {
			if err := s.Commit(revision-1, qemuPersistentNASPolicy(revision)); err != nil {
				return err
			}
		}
		if err := s.Close(); err != nil {
			return err
		}
		for _, path := range []string{dir, corrupt} {
			if err := writeQEMUStateFixture(path+"/.nas-services.pending", pending); err != nil {
				return err
			}
		}
		if err := writeQEMUStateFixture(corrupt+"/nas-services.json", []byte("{truncated")); err != nil {
			return err
		}
		for _, path := range []string{dir, corrupt, root} {
			if err := syncQEMUStateDirectory(path); err != nil {
				return err
			}
		}
		return nil
	}
	if phase != "verify" {
		return errors.New("invalid NAS policy fixture phase")
	}
	s, err := naspolicystore.Open(dir)
	if err != nil {
		return err
	}
	defer s.Close()
	got, err := s.Load()
	if err != nil || !reflect.DeepEqual(got, qemuPersistentNASPolicy(2)) {
		return errors.New("NAS policy changed across boots")
	}
	bad := qemuPersistentNASPolicy(3)
	bad.ISCSI.VolumeRevision = 2
	if err := s.Commit(2, bad); !errors.Is(err, naspolicystore.ErrInvalid) {
		return errors.New("mixed NAS policy accepted")
	}
	if err := s.Commit(1, qemuPersistentNASPolicy(2)); !errors.Is(err, naspolicystore.ErrConflict) {
		return errors.New("stale NAS writer accepted")
	}
	for name, want := range map[string][]byte{"nas-services.json": []byte("{truncated"), ".nas-services.pending": pending} {
		data, err := os.ReadFile(corrupt + "/" + name)
		if err != nil || !bytes.Equal(data, want) {
			return errors.New("NAS corruption evidence changed")
		}
	}
	if broken, err := naspolicystore.Open(corrupt); !errors.Is(err, naspolicystore.ErrInvalid) {
		if broken != nil {
			broken.Close()
		}
		return errors.New("NAS corruption accepted")
	}
	if data, err := os.ReadFile(dir + "/.nas-services.pending"); err != nil || !bytes.Equal(data, pending) {
		return errors.New("NAS pending evidence changed")
	}
	if err := s.Commit(2, qemuPersistentNASPolicy(3)); err != nil {
		return err
	}
	if err := s.Close(); err != nil {
		return err
	}
	s, err = naspolicystore.Open(dir)
	if err != nil {
		return err
	}
	defer s.Close()
	got, err = s.Load()
	if err != nil || !reflect.DeepEqual(got, qemuPersistentNASPolicy(3)) {
		return errors.New("post-boot NAS commit did not reopen")
	}
	for _, name := range []string{"shares.json", "file-services.json"} {
		if _, err := os.Lstat(dir + "/" + name); !errors.Is(err, os.ErrNotExist) {
			return errors.New("legacy state created by NAS store")
		}
	}
	if err := s.Close(); err != nil {
		return err
	}
	if err := exerciseQEMUNASPolicyOwner(dir); err != nil {
		return err
	}
	fmt.Println("PHANTOWD_NAS_POLICY_STATE_READY protocols=smb,nfs,iscsi atomic_revision=true nonempty=true after_reboot=true pending_preserved=true corrupt_refused=true stale_writer_denied=true activation=false scope=disposable-qemu-only")
	return nil
}

// This is called only by the generated-media two-boot harness. Leases retain
// desired state, not real services/backings. The mutation is confined to its
// synthetic nas-services.json; exact byte restoration must not clear review.
func exerciseQEMUNASPolicyOwner(dir string) error {
	ctx := context.Background()
	o, err := naspolicystore.OpenOwner(dir)
	if err != nil {
		return err
	}
	defer o.Close()
	first, err := o.Acquire(ctx, 3)
	if err != nil {
		return err
	}
	defer first.Release()
	second, err := o.Acquire(ctx, 3)
	if err != nil {
		return err
	}
	defer second.Release()
	got, err := first.Snapshot(ctx)
	if err != nil || !reflect.DeepEqual(got, qemuPersistentNASPolicy(3)) {
		return errors.New("policy owner did not retain coherent rebooted state")
	}
	if !errors.Is(o.Commit(ctx, 3, qemuPersistentNASPolicy(4)), naspolicystore.ErrBusy) ||
		!errors.Is(o.Close(), naspolicystore.ErrBusy) {
		return errors.New("live policy lease did not fence mutation or close")
	}
	if err := first.Release(); err != nil {
		return err
	}
	if !errors.Is(o.Commit(ctx, 3, qemuPersistentNASPolicy(4)), naspolicystore.ErrBusy) {
		return errors.New("second policy lease lost")
	}
	if err := second.Release(); err != nil {
		return err
	}
	if err := o.Commit(ctx, 3, qemuPersistentNASPolicy(4)); err != nil {
		return err
	}
	lease, err := o.Acquire(ctx, 4)
	if err != nil {
		return err
	}
	defer lease.Release()
	got, err = lease.Snapshot(ctx)
	if err != nil || !reflect.DeepEqual(got, qemuPersistentNASPolicy(4)) {
		return errors.New("policy owner epoch did not advance coherently")
	}
	before, err := os.ReadFile(dir + "/nas-services.json")
	if err != nil {
		return err
	}
	if err := overwriteQEMUNASPolicyFixture(dir, []byte("{interrupted")); err != nil {
		return err
	}
	if err := overwriteQEMUNASPolicyFixture(dir, before); err != nil {
		return err
	}
	for attempt := 0; attempt < 2; attempt++ {
		if !errors.Is(lease.Verify(ctx), naspolicystore.ErrReview) ||
			!errors.Is(o.Commit(ctx, 4, qemuPersistentNASPolicy(5)), naspolicystore.ErrReview) {
			return errors.New("restored policy revived owner or allowed retry")
		}
		if extra, err := o.Acquire(ctx, 4); !errors.Is(err, naspolicystore.ErrReview) {
			if extra != nil {
				extra.Release()
			}
			return errors.New("review admitted new policy lease")
		}
	}
	if !errors.Is(o.Close(), naspolicystore.ErrBusy) {
		return errors.New("policy review abandoned live claim")
	}
	if other, err := naspolicystore.Open(dir); !errors.Is(err, naspolicystore.ErrBusy) {
		if other != nil {
			other.Close()
		}
		return errors.New("policy review abandoned directory lock")
	}
	if after, err := os.ReadFile(dir + "/nas-services.json"); err != nil || !bytes.Equal(after, before) {
		return errors.New("policy review changed restored evidence")
	}
	if err := lease.Release(); err != nil {
		return err
	}
	if _, err := o.Snapshot(ctx); !errors.Is(err, naspolicystore.ErrReview) {
		return errors.New("policy release cleared review")
	}
	if err := o.Close(); err != nil {
		return err
	}
	fmt.Println("PHANTOWD_NAS_POLICY_OWNER_READY protocols=smb,nfs,iscsi revision_leases=true publication_fenced=true close_fenced=true restored_mutation_review=true flock_retained=true no_retry=true activation=false scope=disposable-qemu-only")
	return nil
}

// Existing generated file only; never create a missing policy or follow a link.
// This deliberately violates the Owner's writer contract solely in this fixture.
func overwriteQEMUNASPolicyFixture(dir string, data []byte) error {
	fd, err := unix.Open(dir+"/nas-services.json", unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), "qemu-policy-mutation")
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&07777 != 0600 ||
		st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 {
		f.Close()
		return errors.New("unexpected generated policy mutation object")
	}
	if err := f.Truncate(0); err != nil {
		f.Close()
		return err
	}
	n, writeErr := f.Write(data)
	if n != len(data) && writeErr == nil {
		writeErr = errors.New("short fixture mutation")
	}
	return errors.Join(writeErr, f.Sync(), f.Close())
}
