//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccountstore"
)

// Called only by the guarded disposable two-boot state harness or host temp-dir
// tests. The registry is real; no Unix account/passdb operations are performed.
func exerciseQEMUServiceAccounts(root, phase string) error {
	dir := root + "/service-identities"
	if phase != "seed" && phase != "verify" {
		return errors.New("unknown identity fixture phase")
	}
	if phase == "seed" {
		if err := os.Mkdir(dir, 0700); err != nil {
			return err
		}
	}
	s, err := serviceaccountstore.Open(dir)
	if err != nil {
		return err
	}
	defer s.Close()
	reserved := serviceaccounts.Reservations{UIDs: []uint32{20000}, GIDs: []uint32{20001}, Names: []string{}}
	if phase == "seed" {
		if err := s.Initialize(20000, 20010); err != nil {
			return err
		}
		if err := s.Create(1, "retired", "retired", reserved); err != nil {
			return err
		}
		if err := s.SetState(2, "retired", serviceaccounts.Retired); err != nil {
			return err
		}
		if err := s.Create(3, "fixture-reader", "qreader", reserved); err != nil {
			return err
		}
		if err := s.SetState(4, "fixture-reader", serviceaccounts.Enabled); err != nil {
			return err
		}
		if err := s.Close(); err != nil {
			return err
		}
		if err := syncQEMUStateDirectory(dir); err != nil {
			return err
		}
		return syncQEMUStateDirectory(root)
	}
	r, err := s.Load()
	if err != nil || r.Revision != 5 || len(r.Accounts) != 2 ||
		r.Accounts[0] != (serviceaccounts.Account{ID: "retired", Name: "retired", UID: 20002, GID: 20002, State: serviceaccounts.Retired}) ||
		r.Accounts[1] != (serviceaccounts.Account{ID: "fixture-reader", Name: "qreader", UID: 20003, GID: 20003, State: serviceaccounts.Enabled}) {
		return errors.New("identity reservations changed after boot")
	}
	bound, err := r.BindShares(qemuPersistentPolicy(3))
	if err != nil || len(bound.Accounts) != 1 || bound.Accounts[0] != r.Accounts[1] {
		return errors.New("persisted share identity mismatch")
	}
	if err := s.Create(5, "new-id", "retired", reserved); !errors.Is(err, serviceaccounts.ErrCollision) {
		return errors.New("retired name was reused after boot")
	}
	if err := s.SetState(5, "retired", serviceaccounts.Enabled); !errors.Is(err, serviceaccounts.ErrTransition) {
		return errors.New("retired identity resurrected")
	}
	if err := s.Create(4, "stale", "stale", reserved); !errors.Is(err, serviceaccounts.ErrConflict) {
		return errors.New("stale identity writer accepted")
	}
	if err := s.Create(5, "next", "next", reserved); err != nil {
		return err
	}
	r, err = s.Load()
	if err != nil || r.Revision != 6 || len(r.Accounts) != 3 || r.Accounts[2].UID != 20004 {
		return errors.New("retired numeric identity reused")
	}
	fmt.Println("PHANTOWD_SERVICE_IDENTITIES_READY after_reboot=true retired_ids_reserved=true stale_writer_denied=true share_binding=true provisioned=false scope=disposable-qemu-only")
	return s.Close()
}
