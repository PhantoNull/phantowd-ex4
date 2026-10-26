//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
)

func TestNASPolicyBackupPreservesAllProtocolsFromOriginalOwner(t *testing.T) {
	owner := nasStateTestOwner(t)
	large := qemuPersistentNASPolicy(2)
	large.ISCSI.Backings[0].CapacityBytes = (1 << 63) - 512
	if err := owner.Commit(context.Background(), 1, large); err != nil {
		t.Fatal(err)
	}
	auth, cookie := newTestAuth(t)
	h := newHandlerWithNASPolicy(nil, nil, nil, nil, auth, nil, nil, nil, newNASStateHandler(auth, owner))
	r := shareReadRequest(cookie)
	r.URL.Path = "/api/v1/nas-services/backup"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var reply struct {
		Format        string           `json:"format"`
		SchemaVersion int              `json:"schema_version"`
		Configuration naspolicy.Config `json:"configuration"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &reply) != nil || reply.Format != "phantowd-nas-policy-backup" || reply.SchemaVersion != 1 ||
		!reflect.DeepEqual(reply.Configuration, large) || reply.Configuration.Validate() != nil ||
		w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Content-Disposition") != `attachment; filename="phantowd-nas-services.json"` {
		t.Fatal("complete desired NAS backup unavailable", w.Code, w.Body.String())
	}
	current, err := owner.Snapshot(context.Background())
	if err != nil || !reflect.DeepEqual(current, reply.Configuration) {
		t.Fatal("backup changed original policy")
	}
}
