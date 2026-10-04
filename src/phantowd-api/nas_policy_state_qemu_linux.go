//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsipolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicystore"
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
	fmt.Println("PHANTOWD_NAS_POLICY_STATE_READY protocols=smb,nfs,iscsi atomic_revision=true nonempty=true after_reboot=true pending_preserved=true corrupt_refused=true stale_writer_denied=true activation=false scope=disposable-qemu-only")
	return nil
}
