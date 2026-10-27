//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
)

func TestNASFileServiceEditorReadsTheOriginalOwner(t *testing.T) {
	owner := nasStateTestOwner(t)
	auth, cookie := newTestAuth(t)
	h := newHandlerWithNASPolicy(nil, nil, nil, nil, auth, nil, nil, nil, newNASStateHandler(auth, owner))
	r := shareReadRequest(cookie)
	r.URL.Path = serviceStatePath
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var reply serviceStateResponse
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &reply) != nil || !reply.Initialized || reply.Configuration == nil ||
		!reflect.DeepEqual(*reply.Configuration, qemuPersistentNASPolicy(1).FileServices) || reply.Applied || reply.ActivationAvailable {
		t.Fatal("configured editor did not read the original NAS Owner", w.Code, w.Body.String())
	}
}

type nasEditorCancelledSnapshot struct {
	nasStateAuthority
	ctx    context.Context
	cancel context.CancelFunc
}

func (s nasEditorCancelledSnapshot) Snapshot(ctx context.Context) (naspolicy.Config, error) {
	if ctx != s.ctx {
		return naspolicy.Config{}, naspolicy.ErrInvalid
	}
	c, err := s.nasStateAuthority.Snapshot(ctx)
	s.cancel()
	return c, err
}

func TestNASFileServiceEditorCancellationAfterSnapshotNeverCommits(t *testing.T) {
	owner := nasStateTestOwner(t)
	auth, cookie := newTestAuth(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h := newNASStateHandler(auth, nasEditorCancelledSnapshot{owner, ctx, cancel})
	w := httptest.NewRecorder()
	h(w, serviceWriteRequest(auth, cookie, qemuPersistentNASPolicy(2).FileServices).WithContext(ctx))
	got, err := owner.Snapshot(context.Background())
	if w.Code != 400 || ctx.Err() == nil || err != nil || !reflect.DeepEqual(got, qemuPersistentNASPolicy(1)) {
		t.Fatal("request context lost or cancelled request committed", w.Code, err)
	}
}

func TestNASFileServiceEditorRefusalsPreserveTheWholeDocument(t *testing.T) {
	owner := nasStateTestOwner(t)
	auth, cookie := newTestAuth(t)
	h := newHandlerWithNASPolicy(nil, nil, nil, nil, auth, nil, nil, nil, newNASStateHandler(auth, owner))
	for _, tc := range []struct {
		name   string
		alter  func(*http.Request)
		status int
	}{
		{"session", func(r *http.Request) { r.Header.Del("Cookie") }, 401},
		{"csrf", func(r *http.Request) { r.Header.Del("X-PhantoWD-CSRF") }, 403},
		{"origin", func(r *http.Request) { r.Header.Set("Origin", "https://foreign.invalid") }, 403},
		{"malformed", func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader(`{"private-marker":true}`)) }, 422},
		{"unbounded-stream", func(r *http.Request) {
			r.ContentLength, r.Body = -1, io.NopCloser(strings.NewReader(strings.Repeat(" ", fileservice.MaxConfigBytes+1)))
		}, 413},
		{"cancelled", func(r *http.Request) {
			ctx, cancel := context.WithCancel(r.Context())
			cancel()
			*r = *r.WithContext(ctx)
		}, 400},
		{"nfs-source-rebind", func(r *http.Request) {
			c := qemuPersistentNASPolicy(2).FileServices
			c.NFS.Exports[0].RelativePath = "other-books"
			*r = *serviceWriteRequest(auth, cookie, c)
		}, 422},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := serviceWriteRequest(auth, cookie, qemuPersistentNASPolicy(2).FileServices)
			tc.alter(r)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			got, err := owner.Snapshot(context.Background())
			if w.Code != tc.status || strings.Contains(w.Body.String(), "private-marker") || err != nil || !reflect.DeepEqual(got, qemuPersistentNASPolicy(1)) {
				t.Fatal("refusal changed full NAS policy or disclosed input", w.Code, tc.status, w.Body.String(), err)
			}
		})
	}
}

func TestNASFileServiceEditorBackupAndRestoreUseTheSamePolicy(t *testing.T) {
	owner := nasStateTestOwner(t)
	auth, cookie := newTestAuth(t)
	h := newHandlerWithNASPolicy(nil, nil, nil, nil, auth, nil, nil, nil, newNASStateHandler(auth, owner))
	r := shareReadRequest(cookie)
	r.URL.Path = serviceBackupPath
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var backup fileservice.Backup
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &backup) != nil || backup.Format != fileservice.BackupFormat ||
		!reflect.DeepEqual(backup.Configuration, qemuPersistentNASPolicy(1).FileServices) {
		t.Fatal("backup did not project the original full policy", w.Code, w.Body.String())
	}
	for _, rebind := range []bool{false, true} {
		next := qemuPersistentNASPolicy(2).FileServices
		want := 200
		if rebind {
			next.Shares.Volumes[0].FilesystemUUID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
			next.Shares.Shares = next.Shares.Shares[:0]
			next.NFS.Exports = next.NFS.Exports[:0]
			want = 422
		}
		data, err := fileservice.EncodeBackup(next)
		if err != nil {
			t.Fatal(err)
		}
		r := serviceWriteRequest(auth, cookie, next)
		r.Method, r.URL.Path = http.MethodPost, serviceRestorePreviewPath
		r.Body, r.ContentLength = io.NopCloser(bytes.NewReader(data)), int64(len(data))
		r.Header.Set(serviceExpectedRevisionHeader, "1")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatal("restore preview did not qualify the full policy", w.Code, want, w.Body.String())
		}
		got, err := owner.Snapshot(context.Background())
		if err != nil || !reflect.DeepEqual(got, qemuPersistentNASPolicy(1)) {
			t.Fatal("restore preview changed saved state", err)
		}
	}
}

func TestNASFileServiceEditorSavesWithoutReplacingISCSI(t *testing.T) {
	owner := nasStateTestOwner(t)
	auth, cookie := newTestAuth(t)
	h := newHandlerWithNASPolicy(nil, nil, nil, nil, auth, nil, nil, nil, newNASStateHandler(auth, owner))
	next := qemuPersistentNASPolicy(2).FileServices
	claim, err := owner.Acquire(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer claim.Release()
	for _, want := range []int{503, 200, 409} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, serviceWriteRequest(auth, cookie, next))
		if w.Code != want {
			t.Fatal("editor save boundary", w.Code, want, w.Body.String())
		}
		if want == 503 {
			if err := claim.Release(); err != nil {
				t.Fatal(err)
			}
		}
	}
	got, err := owner.Snapshot(context.Background())
	want := qemuPersistentNASPolicy(1)
	want.Revision, want.FileServices = 2, next
	want.ISCSI.Revision, want.ISCSI.VolumeRevision = 2, 2
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("editor replaced the other protocol or failed to advance one coherent revision", err)
	}
}
