//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"errors"
	"os"
	"reflect"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsipolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicystore"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/nfsconfig"
)

// Dedicated synthetic state only, not a product bootstrap/activation token.
// Keep the actual policy Store/flock until the fixture's NFS consumers stop.
type qemuNFSRebootPolicy struct {
	nfsconfig.Preview
	store     *naspolicystore.Store
	directory string
	expected  naspolicy.Config
	failed    bool
}

func qemuNFSRebootConfig() naspolicy.Config {
	volumes, policy := qemuNFSFixturePolicy()
	return naspolicy.Config{Format: naspolicy.Format, SchemaVersion: 1, Revision: 1,
		FileServices: fileservice.Config{Format: fileservice.ConfigFormat, SchemaVersion: 1,
			Revision: 1, Shares: volumes, NFS: policy},
		ISCSI: iscsipolicy.Policy{Format: iscsipolicy.Format, SchemaVersion: 1, Revision: 1,
			VolumeRevision: 1, Backings: []iscsipolicy.Backing{}, Targets: []iscsipolicy.Target{}}}
}

// Attempt only invalid transitions on the fixture's original held Store.
// Both attempts must refuse before publication; no repair/retry is permitted.
func verifyQEMUNFSRebootBindingRefusal(policy *qemuNFSRebootPolicy) error {
	if err := policy.Check(); err != nil {
		return err
	}
	for _, kind := range []string{"root", "filesystem"} {
		next := qemuNFSRebootConfig()
		next.Revision, next.FileServices.Revision, next.FileServices.Shares.Revision = 2, 2, 2
		next.FileServices.NFS.Revision, next.FileServices.NFS.VolumeRevision = 2, 2
		next.ISCSI.Revision, next.ISCSI.VolumeRevision = 2, 2
		if kind == "root" {
			next.FileServices.NFS.Exports[0].RelativePath = "unrelated-root"
		} else {
			next.FileServices.Shares.Volumes[0].FilesystemUUID = "66666666-7777-8888-9999-aaaaaaaaaaaa"
		}
		if next.Validate() != nil || !errors.Is(policy.store.Commit(1, next), naspolicystore.ErrInvalid) {
			return errors.New("NFS reboot retained export rebinding not refused")
		}
		if err := policy.Check(); err != nil {
			return err
		}
	}
	return nil
}

func prepareQEMUNFSRebootPolicy(root, phase string) (*qemuNFSRebootPolicy, error) {
	if phase != "seed" && phase != "verify" {
		return nil, errors.New("unknown NFS reboot policy phase")
	}
	directory := root + "/nfs-reboot/policy"
	if phase == "seed" {
		if err := os.Mkdir(root+"/nfs-reboot", 0700); err != nil {
			return nil, err
		}
		if err := os.Mkdir(directory, 0700); err != nil {
			return nil, err
		}
	}
	// Pending/unknown evidence refuses BEFORE writer Open; never use its pending
	// cleanup or another fixture's deliberately uncertain state to force startup.
	entries, err := os.ReadDir(directory)
	if err != nil || (phase == "seed" && len(entries) != 0) ||
		(phase == "verify" && (len(entries) != 1 || entries[0].Name() != "nas-services.json")) {
		return nil, errors.New("NFS reboot policy census refused")
	}
	store, err := naspolicystore.Open(directory)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*qemuNFSRebootPolicy, error) {
		return nil, errors.Join(err, store.Close())
	}
	expected := qemuNFSRebootConfig()
	if phase == "seed" {
		if err := store.Commit(0, expected); err != nil {
			return fail(err)
		}
	}
	current, err := store.Load()
	if err != nil || !reflect.DeepEqual(current, expected) {
		return fail(errors.New("NFS reboot policy is not the confirmed fixture"))
	}
	preview, err := nfsconfig.Build(current.FileServices.NFS, current.FileServices.Shares)
	if err != nil {
		return fail(err)
	}
	return &qemuNFSRebootPolicy{Preview: preview, store: store, directory: directory, expected: expected}, nil
}

func (p *qemuNFSRebootPolicy) Check() error {
	if p == nil || p.store == nil || p.failed {
		return errors.New("NFS reboot policy unavailable")
	}
	entries, err := os.ReadDir(p.directory)
	if err != nil || len(entries) != 1 || entries[0].Name() != "nas-services.json" {
		p.failed = true
		return errors.New("NFS reboot policy evidence changed")
	}
	current, err := p.store.Load()
	if err != nil || !reflect.DeepEqual(current, p.expected) {
		p.failed = true
		return errors.New("NFS reboot policy changed")
	}
	return nil
}

func (p *qemuNFSRebootPolicy) Close() error {
	p.failed = true
	return p.store.Close()
}
