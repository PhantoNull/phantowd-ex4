//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservicestore"
)

// Real private local policy store, no block device, root operation or service.
func TestServiceBackupPersistentRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	s, err := fileservicestore.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if s != nil {
			s.Close()
		}
	}()
	backend := &serviceStateBackend{load: func() (*fileservice.Config, error) {
		c, err := s.Load()
		if errors.Is(err, fileservicestore.ErrNotInitialized) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		return &c, nil
	}, commit: func(expected uint64, c fileservice.Config) error {
		err := s.Commit(expected, c)
		if errors.Is(err, fileservicestore.ErrConflict) {
			return errServiceStateConflict
		}
		return err
	}}
	auth, cookie := newTestAuth(t)
	h := newHandlerWithServiceState(nil, nil, nil, nil, auth, nil, backend)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, restoreRequest(t, auth, cookie, "0"))
	var preview struct {
		Configuration fileservice.Config `json:"configuration"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &preview) != nil {
		t.Fatal(w.Code, w.Body.String())
	}
	if _, err := s.Load(); !errors.Is(err, fileservicestore.ErrNotInitialized) {
		t.Fatal("preview wrote actual store", err)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, serviceWriteRequest(auth, cookie, preview.Configuration))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = nil
	s, err = fileservicestore.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := s.Load()
	if err != nil || !reflect.DeepEqual(loaded, preview.Configuration) {
		t.Fatal("restored policy not durable across reopen", err)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, serviceWriteRequest(auth, cookie, preview.Configuration))
	if w.Code != 409 {
		t.Fatal("repeated restore save did not conflict", w.Code)
	}
}
