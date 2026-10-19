//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestQEMUServiceStateBackendRejectsRetainedNFSBindingOverHTTP(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	backend, closeState, err := openDevelopmentServiceState(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer closeState()
	base := qemuPersistentServices(1)
	if err := backend.commit(0, base); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(dir, "file-services.json"))
	if err != nil {
		t.Fatal(err)
	}
	auth, cookie := newTestAuth(t)
	handler := newHandlerWithServiceState(nil, nil, nil, nil, auth, nil, backend)
	next := qemuPersistentServices(2)
	next.NFS.Exports[0].RelativePath = "unrelated-root"
	reply := httptest.NewRecorder()
	handler.ServeHTTP(reply, serviceWriteRequest(auth, cookie, next))
	if reply.Code != 422 || reply.Body.String() != "{\"error\":\"invalid_service_configuration\"}\n" {
		t.Fatal("known pre-effect refusal is not distinguished from an unknown save", reply.Code, reply.Body.String())
	}
	after, err := os.ReadFile(filepath.Join(dir, "file-services.json"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("rejected request changed current policy", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, ".file-services.pending")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("rejected request created pending state", err)
	}
	valid := httptest.NewRecorder()
	handler.ServeHTTP(valid, serviceWriteRequest(auth, cookie, qemuPersistentServices(2)))
	if valid.Code != 200 {
		t.Fatal("known rejection made a healthy store unavailable", valid.Code, valid.Body.String())
	}
}

func TestQEMUServiceStateBackendCorruptLoadIsNotARequestRejection(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	backend, closeState, err := openDevelopmentServiceState(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer closeState()
	if err := backend.commit(0, qemuPersistentServices(1)); err != nil {
		t.Fatal(err)
	}
	const corrupt = "{private truncated policy"
	if err := os.WriteFile(filepath.Join(dir, "file-services.json"), []byte(corrupt), 0600); err != nil {
		t.Fatal(err)
	}
	auth, cookie := newTestAuth(t)
	handler := newHandlerWithServiceState(nil, nil, nil, nil, auth, nil, backend)
	request := shareReadRequest(cookie)
	request.URL.Path = serviceStatePath
	reply := httptest.NewRecorder()
	handler.ServeHTTP(reply, request)
	if reply.Code != http.StatusServiceUnavailable || reply.Body.String() != "{\"error\":\"service_configuration_unavailable\"}\n" {
		t.Fatal("persistent corruption became a known request rejection", reply.Code, reply.Body.String())
	}
	write := httptest.NewRecorder()
	handler.ServeHTTP(write, serviceWriteRequest(auth, cookie, qemuPersistentServices(2)))
	if write.Code != http.StatusServiceUnavailable || write.Body.String() != "{\"error\":\"service_configuration_unavailable\"}\n" {
		t.Fatal("commit against corrupt current policy became a known request rejection", write.Code, write.Body.String())
	}
	if current, err := os.ReadFile(filepath.Join(dir, "file-services.json")); err != nil || string(current) != corrupt {
		t.Fatal("read error repaired or removed corrupt evidence", err)
	}
}

func TestQEMUServiceStateBackendHTTPRefusalTransports(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := exerciseQEMUServiceHTTP(dir, 0, 1, false); err != nil {
		t.Fatal(err)
	}
	if err := exerciseQEMUServiceHTTP(dir, 1, 2, true); err != nil {
		t.Fatal(err)
	}
}

func TestQEMUServiceStateBackend(t *testing.T) {
	backend, closeDisabled, err := openDevelopmentServiceState("")
	if err != nil || backend != nil || closeDisabled == nil || closeDisabled() != nil {
		t.Fatal("disabled backend changed")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	backend, closeState, err := openDevelopmentServiceState(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer closeState()
	if c, err := backend.load(); err != nil || c != nil {
		t.Fatal("uninitialized state not preserved", err)
	}
	if _, closeOther, err := openDevelopmentServiceState(dir); err == nil {
		closeOther()
		t.Fatal("competing owner accepted")
	}
	want := qemuPersistentServices(1)
	if err := backend.commit(0, want); err != nil {
		t.Fatal(err)
	}
	if err := backend.commit(0, want); !errors.Is(err, errServiceStateConflict) {
		t.Fatal("stale revision was not translated", err)
	}
	if err := closeState(); err != nil {
		t.Fatal(err)
	}
	if _, err := backend.load(); err == nil {
		t.Fatal("closed store readable")
	}
	if err := backend.commit(1, qemuPersistentServices(2)); err == nil {
		t.Fatal("closed store writable")
	}
	reopened, closeAgain, err := openDevelopmentServiceState(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer closeAgain()
	if got, err := reopened.load(); err != nil || got == nil || !reflect.DeepEqual(*got, want) {
		t.Fatal("committed state lost", err)
	}
	for _, invalid := range []string{filepath.Join(dir, "missing"), "."} {
		if _, closeOther, err := openDevelopmentServiceState(invalid); err == nil {
			closeOther()
			t.Fatal("invalid state accepted")
		}
	}
}
