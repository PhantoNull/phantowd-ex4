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

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
)

func nasRestorePost(auth *authController, cookie *http.Cookie, data []byte, expected string) *http.Request {
	r := serviceWriteRequest(auth, cookie, serviceConfigFixture(2))
	r.Method, r.URL.Path = http.MethodPost, "/api/v1/nas-services/restore-preview"
	r.Body, r.ContentLength = io.NopCloser(bytes.NewReader(data)), int64(len(data))
	r.Header.Set(serviceExpectedRevisionHeader, expected)
	return r
}

func nasRestoreRevision(c naspolicy.Config, r uint64) naspolicy.Config {
	c.Revision, c.FileServices.Revision, c.FileServices.Shares.Revision = r, r, r
	c.FileServices.NFS.Revision, c.FileServices.NFS.VolumeRevision = r, r
	c.ISCSI.Revision, c.ISCSI.VolumeRevision = r, r
	return c
}

func TestNASPolicyRestorePreviewReturnsLosslessWholeCandidate(t *testing.T) {
	owner := nasStateTestOwner(t)
	auth, cookie := newTestAuth(t)
	h := newHandlerWithNASPolicy(nil, nil, nil, nil, auth, nil, nil, nil, newNASStateHandler(auth, owner))
	desired := qemuPersistentNASPolicy(1)
	desired.ISCSI.Backings[0].CapacityBytes = (1 << 63) - 512
	data, _ := json.Marshal(map[string]any{"format": nasBackupFormat, "schema_version": 1, "configuration": desired})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, nasRestorePost(auth, cookie, data, "1"))
	var reply struct {
		SchemaVersion int    `json:"schema_version"`
		Scope         string `json:"scope"`
		Expected      uint64 `json:"expected_revision"`
		Candidate     string `json:"candidate_json"`
		Saved         bool   `json:"saved"`
		Applied       bool   `json:"applied"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &reply) != nil || reply.SchemaVersion != 1 ||
		reply.Scope != "nas-policy-restore-preview-only" || reply.Expected != 1 || reply.Saved || reply.Applied {
		t.Fatal("complete NAS restore preview unavailable", w.Code, w.Body.String())
	}
	candidate, err := naspolicy.Decode(bytes.NewReader([]byte(reply.Candidate)))
	var presentation struct {
		Values map[string]string `json:"backing_capacities"`
	}
	if json.Unmarshal(w.Body.Bytes(), &presentation) != nil || presentation.Values[string(desired.ISCSI.Backings[0].ID)] != "9223372036854775296" {
		t.Fatal("restore review lost exact decimal backing capacity", presentation.Values)
	}
	want := nasRestoreRevision(desired, 2)
	if err != nil || !reflect.DeepEqual(candidate, want) {
		t.Fatal("preview lost desired definitions, uint64 precision or revision coherence", err)
	}
	current, err := owner.Snapshot(context.Background())
	if err != nil || !reflect.DeepEqual(current, qemuPersistentNASPolicy(1)) {
		t.Fatal("preview changed the original Owner", err)
	}
	r := loopbackRequest(http.MethodGet, nasStatePath, nil)
	r.Header.Set("Origin", auth.allowedOrigin)
	r.AddCookie(cookie)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var displayed struct {
		Values map[string]string `json:"backing_capacities"`
	}
	expectedBytes, _ := json.Marshal(current.ISCSI.Backings[0].CapacityBytes)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &displayed) != nil || displayed.Values[string(current.ISCSI.Backings[0].ID)] != string(expectedBytes) {
		t.Fatal("saved-policy review lost exact capacity", w.Code, displayed.Values)
	}
	lease, err := owner.Acquire(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	for i, status := range []int{503, 200, 409} {
		if i == 1 {
			if err := lease.Release(); err != nil {
				t.Fatal(err)
			}
		}
		r := serviceWriteRequest(auth, cookie, candidate.FileServices)
		r.URL.Path = nasStatePath
		r.Body, r.ContentLength = io.NopCloser(strings.NewReader(reply.Candidate)), int64(len(reply.Candidate))
		w = httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != status {
			t.Fatal("existing complete PUT lost busy/save/conflict semantics", w.Code, status)
		}
	}
	current, err = owner.Snapshot(context.Background())
	if err != nil || !reflect.DeepEqual(current, want) {
		t.Fatal("saved candidate lost desired definitions or uint64 precision", err)
	}
}

func TestNASPolicyRestorePreviewRefusalsPreserveOriginalState(t *testing.T) {
	owner := nasStateTestOwner(t)
	auth, cookie := newTestAuth(t)
	h := newNASStateHandler(auth, owner)
	current := qemuPersistentNASPolicy(1)
	backup := func(c naspolicy.Config) []byte {
		data, _ := json.Marshal(map[string]any{"format": nasBackupFormat, "schema_version": 1, "configuration": c})
		return data
	}
	setBody := func(r *http.Request, data []byte) {
		r.Body, r.ContentLength = io.NopCloser(bytes.NewReader(data)), int64(len(data))
	}
	for _, tc := range []struct {
		name   string
		alter  func(*http.Request)
		status int
	}{
		{"session", func(r *http.Request) { r.Header.Del("Cookie") }, 401},
		{"csrf", func(r *http.Request) { r.Header.Del("X-PhantoWD-CSRF") }, 403},
		{"origin", func(r *http.Request) { r.Header.Set("Origin", "https://foreign.invalid") }, 403},
		{"duplicate-revision", func(r *http.Request) { r.Header.Add(serviceExpectedRevisionHeader, "1") }, 400},
		{"noncanonical-revision", func(r *http.Request) { r.Header.Set(serviceExpectedRevisionHeader, "01") }, 400},
		{"stale", func(r *http.Request) { r.Header.Set(serviceExpectedRevisionHeader, "2") }, 409},
		{"overflow", func(r *http.Request) { r.Header.Set(serviceExpectedRevisionHeader, "18446744073709551615") }, 422},
		{"malformed", func(r *http.Request) { setBody(r, []byte(`{"private-marker":true}`)) }, 422},
		{"duplicate-json", func(r *http.Request) {
			setBody(r, bytes.Replace(backup(current), []byte(`"format":"`+nasBackupFormat+`"`), []byte(`"format":"`+nasBackupFormat+`","format":"`+nasBackupFormat+`"`), 1))
		}, 422},
		{"invalid-utf8", func(r *http.Request) { setBody(r, append([]byte{0xff}, backup(current)...)) }, 422},
		{"too-large", func(r *http.Request) { r.ContentLength = naspolicy.MaxBackupBytes + 1 }, 413},
		{"stream-limit", func(r *http.Request) {
			r.ContentLength, r.Body = -1, io.NopCloser(strings.NewReader(strings.Repeat(" ", naspolicy.MaxBackupBytes+1)))
		}, 413},
		{"retained-nfs-source", func(r *http.Request) {
			c := qemuPersistentNASPolicy(1)
			c.FileServices.NFS.Exports[0].RelativePath = "other-books"
			setBody(r, backup(c))
		}, 422},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := nasRestorePost(auth, cookie, backup(current), "1")
			tc.alter(r)
			w := httptest.NewRecorder()
			h(w, r)
			got, err := owner.Snapshot(context.Background())
			if w.Code != tc.status || strings.Contains(w.Body.String(), "private-marker") || err != nil || !reflect.DeepEqual(got, current) {
				t.Fatal("refused preview changed state or exposed its input", w.Code, tc.status, err)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := httptest.NewRecorder()
	newNASStateHandler(auth, nasEditorCancelledSnapshot{owner, ctx, cancel})(w, nasRestorePost(auth, cookie, backup(current), "1").WithContext(ctx))
	if w.Code != 400 {
		t.Fatal("cancelled snapshot returned a usable preview", w.Code)
	}
}

func TestNASPolicyRestorePreviewComparesExactDefinitionsAcrossRevisions(t *testing.T) {
	owner := nasStateTestOwner(t)
	auth, cookie := newTestAuth(t)
	h := newNASStateHandler(auth, owner)
	const size = uint64(1<<63) - 2048
	current := nasRestoreRevision(qemuPersistentNASPolicy(1), 2)
	current.ISCSI.Backings[0].CapacityBytes = size
	if err := owner.Commit(context.Background(), 1, current); err != nil {
		t.Fatal(err)
	}
	if float64(size) != float64(size+512) {
		t.Fatal("fixture does not exercise a JavaScript precision collision")
	}
	for _, difference := range []uint64{0, 512} {
		desired := nasRestoreRevision(qemuPersistentNASPolicy(1), 9)
		desired.ISCSI.Backings[0].CapacityBytes = size + difference
		data, _ := json.Marshal(map[string]any{"format": nasBackupFormat, "schema_version": 1, "configuration": desired})
		w := httptest.NewRecorder()
		h(w, nasRestorePost(auth, cookie, data, "2"))
		var reply struct {
			Matches *bool `json:"matches_current"`
		}
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &reply) != nil || reply.Matches == nil || *reply.Matches != (difference == 0) {
			t.Fatal("preview must compare all definitions exactly, not rounded numbers or backup revision", w.Code)
		}
	}
	got, err := owner.Snapshot(context.Background())
	if err != nil || !reflect.DeepEqual(got, current) {
		t.Fatal("comparison mutated original policy", err)
	}
}

func TestNASPolicyRestorePreviewSavesAddedDisabledTarget(t *testing.T) {
	owner := nasStateTestOwner(t)
	auth, cookie := newTestAuth(t)
	h := newHandlerWithNASPolicy(nil, nil, nil, nil, auth, nil, nil, nil, newNASStateHandler(auth, owner))
	desired := qemuPersistentNASPolicy(1)
	backing := desired.ISCSI.Backings[0]
	backing.ID, backing.RelativePath, backing.CapacityBytes = "draft-backing", "luns/draft.img", 8192
	target := qemuPersistentNASPolicy(1).ISCSI.Targets[0]
	target.ID, target.Name = "draft-target", "iqn.2026-10.org.example:draft"
	target.LUNs[0].ID, target.LUNs[0].BackingID = "draft-lun", backing.ID
	target.Initiators[0].Name = "iqn.2026-10.org.example:client"
	target.Initiators[0].Authentication.InitiatorSecretRef = "draft-inbound"
	target.Initiators[0].Grants[0].LUNID = target.LUNs[0].ID
	desired.ISCSI.Backings = append(desired.ISCSI.Backings, backing)
	desired.ISCSI.Targets = append(desired.ISCSI.Targets, target)
	data, err := json.Marshal(map[string]any{"format": nasBackupFormat, "schema_version": 1, "configuration": desired})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, nasRestorePost(auth, cookie, data, "1"))
	var reply struct {
		Candidate string `json:"candidate_json"`
		Saved     bool   `json:"saved"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &reply) != nil || reply.Saved {
		t.Fatal("target review unavailable", w.Code)
	}
	current, err := owner.Snapshot(context.Background())
	if err != nil || !reflect.DeepEqual(current, qemuPersistentNASPolicy(1)) {
		t.Fatal("review changed original policy", err)
	}
	candidate, err := naspolicy.Decode(strings.NewReader(reply.Candidate))
	want := nasRestoreRevision(desired, 2)
	if err != nil || !reflect.DeepEqual(candidate, want) || candidate.ISCSI.Targets[1].State != "disabled" {
		t.Fatal("new target or preserved definitions differ", err)
	}
	lease, err := owner.Acquire(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	for index, status := range []int{503, 200, 409} {
		if index == 1 {
			if err := lease.Release(); err != nil {
				t.Fatal(err)
			}
		}
		request := serviceWriteRequest(auth, cookie, candidate.FileServices)
		request.URL.Path = nasStatePath
		request.Body, request.ContentLength = io.NopCloser(strings.NewReader(reply.Candidate)), int64(len(reply.Candidate))
		output := httptest.NewRecorder()
		h.ServeHTTP(output, request)
		if output.Code != status {
			t.Fatal("target addition lost busy/commit/stale semantics", output.Code, status)
		}
	}
	current, err = owner.Snapshot(context.Background())
	if err != nil || !reflect.DeepEqual(current, want) {
		t.Fatal("saved target changed unrelated definitions", err)
	}
}

func TestNASPolicyRestorePreviewSavesAdditionalLUN(t *testing.T) {
	owner := nasStateTestOwner(t)
	auth, cookie := newTestAuth(t)
	h := newHandlerWithNASPolicy(nil, nil, nil, nil, auth, nil, nil, nil, newNASStateHandler(auth, owner))
	desired := qemuPersistentNASPolicy(1)
	backing := desired.ISCSI.Backings[0]
	backing.ID, backing.RelativePath, backing.CapacityBytes = "extra-backing", "luns/extra.img", 8192
	target := &desired.ISCSI.Targets[0]
	lun, grant := target.LUNs[0], target.Initiators[0].Grants[0]
	lun.ID, lun.Number, lun.BackingID, grant.LUNID = "extra-lun", 65535, backing.ID, "extra-lun"
	target.LUNs, target.Initiators[0].Grants = append(target.LUNs, lun), append(target.Initiators[0].Grants, grant)
	desired.ISCSI.Backings = append(desired.ISCSI.Backings, backing)
	input, err := json.Marshal(desired)
	if err != nil {
		t.Fatal(err)
	}
	preview := httptest.NewRecorder()
	h.ServeHTTP(preview, iscsiPreviewRequest(auth, cookie, string(input)))
	if preview.Code != 200 {
		t.Fatal("additional LUN preview refused", preview.Code)
	}
	data, _ := json.Marshal(map[string]any{"format": nasBackupFormat, "schema_version": 1, "configuration": desired})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, nasRestorePost(auth, cookie, data, "1"))
	var reply struct {
		Candidate string `json:"candidate_json"`
		Saved     bool   `json:"saved"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &reply) != nil || reply.Saved {
		t.Fatal("additional LUN review unavailable", w.Code)
	}
	current, err := owner.Snapshot(context.Background())
	if err != nil || !reflect.DeepEqual(current, qemuPersistentNASPolicy(1)) {
		t.Fatal("preview changed original policy", err)
	}
	candidate, err := naspolicy.Decode(strings.NewReader(reply.Candidate))
	want := nasRestoreRevision(desired, 2)
	if err != nil || !reflect.DeepEqual(candidate, want) {
		t.Fatal("additional LUN or preserved definitions differ", err)
	}
	for _, status := range []int{200, 409} {
		request := serviceWriteRequest(auth, cookie, candidate.FileServices)
		request.URL.Path = nasStatePath
		request.Body, request.ContentLength = io.NopCloser(strings.NewReader(reply.Candidate)), int64(len(reply.Candidate))
		output := httptest.NewRecorder()
		h.ServeHTTP(output, request)
		if output.Code != status {
			t.Fatal("additional LUN lost commit/stale semantics", output.Code, status)
		}
	}
	current, err = owner.Snapshot(context.Background())
	if err != nil || !reflect.DeepEqual(current, want) {
		t.Fatal("saved LUN changed unrelated definitions", err)
	}
}

func TestNASPolicyRestorePreviewSavesScopedISCSIEdits(t *testing.T) {
	for _, operation := range []string{"target-state", "lun-access", "grant-access"} {
		t.Run(operation, func(t *testing.T) {
			owner := nasStateTestOwner(t)
			before := nasRestoreRevision(qemuPersistentNASPolicy(1), 2)
			before.ISCSI.Targets[0].LUNs[0].Access = "rw"
			if err := owner.Commit(context.Background(), 1, before); err != nil {
				t.Fatal(err)
			}
			desired := nasRestoreRevision(qemuPersistentNASPolicy(1), 2)
			desired.ISCSI.Targets[0].LUNs[0].Access = "rw"
			switch operation {
			case "target-state":
				desired.ISCSI.Targets[0].State = "enabled"
			case "lun-access":
				desired.ISCSI.Targets[0].LUNs[0].Access = "ro"
			case "grant-access":
				desired.ISCSI.Targets[0].Initiators[0].Grants[0].Access = "rw"
			}
			auth, cookie := newTestAuth(t)
			h := newHandlerWithNASPolicy(nil, nil, nil, nil, auth, nil, nil, nil, newNASStateHandler(auth, owner))
			input, _ := json.Marshal(desired)
			preview := httptest.NewRecorder()
			h.ServeHTTP(preview, iscsiPreviewRequest(auth, cookie, string(input)))
			if preview.Code != 200 {
				t.Fatal("scoped desired preview refused", preview.Code)
			}
			data, _ := json.Marshal(map[string]any{"format": nasBackupFormat, "schema_version": 1, "configuration": desired})
			w := httptest.NewRecorder()
			h.ServeHTTP(w, nasRestorePost(auth, cookie, data, "2"))
			var reply struct {
				Candidate string `json:"candidate_json"`
				Saved     bool   `json:"saved"`
			}
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &reply) != nil || reply.Saved {
				t.Fatal("scoped review unavailable", w.Code)
			}
			current, err := owner.Snapshot(context.Background())
			if err != nil || !reflect.DeepEqual(current, before) {
				t.Fatal("preview mutated baseline", err)
			}
			candidate, err := naspolicy.Decode(strings.NewReader(reply.Candidate))
			want := nasRestoreRevision(desired, 3)
			if err != nil || !reflect.DeepEqual(candidate, want) {
				t.Fatal("scoped candidate or preserved definitions differ", err)
			}
			lease, err := owner.Acquire(context.Background(), 2)
			if err != nil {
				t.Fatal(err)
			}
			defer lease.Release()
			for index, status := range []int{503, 200, 409} {
				if index == 1 {
					if err := lease.Release(); err != nil {
						t.Fatal(err)
					}
				}
				request := serviceWriteRequest(auth, cookie, candidate.FileServices)
				request.URL.Path = nasStatePath
				request.Body, request.ContentLength = io.NopCloser(strings.NewReader(reply.Candidate)), int64(len(reply.Candidate))
				output := httptest.NewRecorder()
				h.ServeHTTP(output, request)
				if output.Code != status {
					t.Fatal("scoped save lost busy/commit/stale semantics", output.Code, status)
				}
			}
			current, err = owner.Snapshot(context.Background())
			if err != nil || !reflect.DeepEqual(current, want) {
				t.Fatal("saved edit changed unrelated definitions", err)
			}
		})
	}
}
