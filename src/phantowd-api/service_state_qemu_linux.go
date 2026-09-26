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

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservicestore"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/nfsconfig"
)

func qemuPersistentServices(revision uint64) fileservice.Config {
	access := "ro"
	if revision == 2 {
		access = "rw"
	}
	shares := qemuPersistentPolicy(revision)
	shares.Shares[0].Grants[0].Access = access
	return fileservice.Config{Format: fileservice.ConfigFormat, SchemaVersion: 1, Revision: revision, Shares: shares,
		NFS: nfsconfig.Policy{Format: nfsconfig.Format, SchemaVersion: 1, Revision: revision, VolumeRevision: revision,
			Exports: []nfsconfig.Export{{ID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", VolumeID: "fixture-volume", RelativePath: "books",
				Clients: []nfsconfig.Client{{Network: "192.0.2.10/32", Access: access, Squash: "all", AnonymousUID: 65534, AnonymousGID: 65534, Security: "sys"}}}}}}
}

// Called only by the existing guarded, generated-disk two-boot fixture (or
// temporary host-directory tests). No runtime service is started or changed.
func exerciseQEMUServiceStatePersistence(root, phase string) error {
	dir, corrupt := root+"/services", root+"/services-corrupt"
	pending, err := json.Marshal(qemuPersistentServices(3))
	if err != nil {
		return err
	}
	if phase == "seed" {
		for _, path := range []string{dir, corrupt} {
			if err := os.Mkdir(path, 0700); err != nil {
				return err
			}
		}
		s, err := fileservicestore.Open(dir)
		if err != nil {
			return err
		}
		defer s.Close()
		for r := uint64(1); r <= 2; r++ {
			if err := s.Commit(r-1, qemuPersistentServices(r)); err != nil {
				return err
			}
		}
		if err := s.Close(); err != nil {
			return err
		}
		for _, path := range []string{dir, corrupt} {
			if err := writeQEMUStateFixture(path+"/.file-services.pending", pending); err != nil {
				return err
			}
		}
		if err := writeQEMUStateFixture(corrupt+"/file-services.json", []byte("{truncated")); err != nil {
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
		return errors.New("invalid service-state phase")
	}
	s, err := fileservicestore.Open(dir)
	if err != nil {
		return err
	}
	defer s.Close()
	got, err := s.Load()
	if err != nil || !reflect.DeepEqual(got, qemuPersistentServices(2)) {
		return errors.New("combined policy changed across boots")
	}
	bad := qemuPersistentServices(3)
	bad.NFS.VolumeRevision = 2
	if err := s.Commit(2, bad); !errors.Is(err, fileservicestore.ErrInvalid) {
		return errors.New("split service revision accepted")
	}
	if err := s.Commit(1, qemuPersistentServices(2)); !errors.Is(err, fileservicestore.ErrConflict) {
		return errors.New("stale service writer accepted")
	}
	if err := s.Commit(2, qemuPersistentServices(3)); err != nil {
		return err
	}
	if err := s.Close(); err != nil {
		return err
	}
	s, err = fileservicestore.Open(dir)
	if err != nil {
		return err
	}
	defer s.Close()
	got, err = s.Load()
	if err != nil || !reflect.DeepEqual(got, qemuPersistentServices(3)) {
		return errors.New("combined post-boot commit did not reopen")
	}
	broken, err := fileservicestore.Open(corrupt)
	if broken != nil {
		broken.Close()
	}
	if !errors.Is(err, fileservicestore.ErrInvalid) {
		return errors.New("corrupt combined state accepted")
	}
	for name, want := range map[string][]byte{"file-services.json": []byte("{truncated"), ".file-services.pending": pending} {
		data, err := os.ReadFile(corrupt + "/" + name)
		if err != nil || !bytes.Equal(data, want) {
			return errors.New("combined corrupt evidence changed")
		}
	}
	fmt.Println("PHANTOWD_SERVICE_STATE_READY protocols=smb,nfs atomic_revision=true after_reboot=true activation=false scope=disposable-qemu-only")
	return nil
}
