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
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/admincredentials"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/revisionstore"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/passwordhash"
)

// Public disposable-fixture passwords, never installed into the panel account.
const qemuAdminBefore = "public-qemu-fixture-before-replacement"
const qemuAdminAfter = "public-qemu-fixture-after-replacement"

// Exact former setup encoding, retained only to generate migration fixtures.
type accountDocument struct {
	Version int                      `json:"version"`
	Admin   admincredentials.Account `json:"admin"`
}

// Only the guarded generated-disk harness and private host temp-dir tests call
// this function. It does not switch the running API's authentication backend.
func exerciseQEMUAdminCredentials(root, phase string) error {
	if phase != "seed" && phase != "verify" {
		return errors.New("unknown administrator fixture phase")
	}
	ctx := context.Background()
	var oldHash string
	if phase == "seed" {
		var err error
		oldHash, err = passwordhash.Hash(ctx, []byte(qemuAdminBefore))
		if err != nil {
			return err
		}
	}
	for _, kind := range []string{"native", "legacy"} {
		dir := root + "/admin-credentials-" + kind
		if phase == "seed" {
			if err := os.Mkdir(dir, 0700); err != nil {
				return err
			}
			if kind == "legacy" {
				data, err := json.Marshal(accountDocument{Version: 1, Admin: admincredentials.Account{Username: "fixture-admin", PasswordHash: oldHash}})
				if err != nil {
					return err
				}
				if err := os.WriteFile(dir+"/accounts.json", data, 0600); err != nil {
					return err
				}
			}
		}
		if err := exerciseQEMUAdminCredentialStore(dir, kind, phase, oldHash); err != nil {
			return err
		}
	}
	if err := syncQEMUStateDirectory(root); err != nil {
		return err
	}
	if phase == "verify" {
		fmt.Println("PHANTOWD_ADMIN_CREDENTIALS_READY after_reboot=true legacy_preserved=true old_password_denied=true replacement_verified=true stale_writer_denied=true scope=store-fixture-only")
		fmt.Println("PHANTOWD_ADMIN_BACKEND_READY after_reboot=true backend=transactional-store login_verified=true scope=qemu-handler-dispatch-only")
		fmt.Println("PHANTOWD_PASSWORD_REBOOT_READY changed_via=authenticated-handler legacy_and_native=true old_password_denied=true scope=clean-qemu-reboot-only")
	}
	return nil
}

func exerciseQEMUAdminCredentialStore(dir, kind, phase, oldHash string) error {
	s, err := admincredentials.Open(dir)
	if err != nil {
		return err
	}
	defer s.Close()
	if phase == "seed" {
		if kind == "native" {
			if err := s.Initialize("fixture-admin", oldHash); err != nil {
				return err
			}
		} else {
			before, err := os.ReadFile(dir + "/accounts.json")
			if err != nil {
				return err
			}
			d, err := s.Load()
			if err != nil || d.Revision != 1 || d.Admin.Username != "fixture-admin" || d.Admin.PasswordHash != oldHash {
				return errors.New("legacy administrator was not preserved")
			}
			after, err := os.ReadFile(dir + "/accounts.json")
			if err != nil || !bytes.Equal(before, after) {
				return errors.New("legacy read rewrote state")
			}
		}
		if err := s.Close(); err != nil {
			return err
		}
		accounts, err := openAccountStore(dir)
		if err != nil {
			return err
		}
		defer accounts.Close()
		auth := newAuthController(accounts, defaultPublicOrigin)
		token, session, err := auth.sessions.create(time.Now())
		if err != nil {
			return err
		}
		body, err := json.Marshal(passwordChangeRequest{CurrentPassword: qemuAdminBefore, NewPassword: qemuAdminAfter})
		if err != nil {
			return err
		}
		r := httptest.NewRequest(http.MethodPost, defaultPublicOrigin+authPasswordPath, bytes.NewReader(body))
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
		r.Header.Set("Origin", defaultPublicOrigin)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-PhantoWD-CSRF", session.csrf)
		w := httptest.NewRecorder()
		auth.serve(w, r)
		if w.Code != http.StatusOK {
			return errors.New("persistent administrator password change refused")
		}
		if _, ok := auth.sessions.find(token, time.Now()); ok {
			return errors.New("password change retained a session")
		}
		if err := accounts.Close(); err != nil {
			return err
		}
		// Valid, private, fully synced but uncommitted old state must not win.
		pending, err := json.Marshal(admincredentials.Document{Version: admincredentials.Version, Revision: 3,
			Admin: admincredentials.Account{Username: "fixture-admin", PasswordHash: oldHash}})
		if err != nil {
			return err
		}
		file, err := os.OpenFile(dir+"/.accounts.pending", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		_, writeErr := file.Write(pending)
		syncErr, closeErr := file.Sync(), file.Close()
		if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
			return err
		}
		return syncQEMUStateDirectory(dir)
	}
	d, err := s.Load()
	if err != nil || d.Version != admincredentials.Version || d.Revision != 2 || d.Admin.Username != "fixture-admin" {
		return errors.New("administrator credential revision changed after reboot")
	}
	if err := s.Replace(1, d.Admin.PasswordHash); !errors.Is(err, revisionstore.ErrConflict) {
		return errors.New("stale administrator replacement accepted")
	}
	if err := s.Initialize("other-admin", d.Admin.PasswordHash); !errors.Is(err, revisionstore.ErrConflict) {
		return errors.New("configured administrator reset accepted")
	}
	if err := s.Close(); err != nil {
		return err
	}
	accounts, err := openAccountStore(dir)
	if err != nil {
		return err
	}
	defer accounts.Close()
	auth := newAuthController(accounts, defaultPublicOrigin)
	for _, attempt := range []struct {
		password string
		status   int
	}{
		{qemuAdminBefore, http.StatusUnauthorized}, {qemuAdminAfter, http.StatusOK},
	} {
		body, err := json.Marshal(loginRequest{Username: "fixture-admin", Password: attempt.password})
		if err != nil {
			return err
		}
		r := httptest.NewRequest(http.MethodPost, defaultPublicOrigin+authLoginPath, bytes.NewReader(body))
		r.Header.Set("Origin", defaultPublicOrigin)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		auth.serve(w, r)
		if w.Code != attempt.status {
			return errors.New("transactional administrator HTTP login mismatch")
		}
		cookies := w.Result().Cookies()
		if attempt.status == http.StatusUnauthorized {
			if len(cookies) != 0 {
				return errors.New("obsolete password issued a cookie")
			}
			continue
		}
		if len(cookies) != 1 {
			return errors.New("administrator login did not issue one cookie")
		}
		r = httptest.NewRequest(http.MethodGet, defaultPublicOrigin+authSessionPath, nil)
		r.AddCookie(cookies[0])
		w = httptest.NewRecorder()
		auth.serve(w, r)
		if w.Code != http.StatusOK {
			return errors.New("transactional administrator session unavailable")
		}
	}
	return accounts.Close()
}
