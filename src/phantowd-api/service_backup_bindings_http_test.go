// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http/httptest"
	"reflect"
	"slices"
	"strconv"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/nfsconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

func restoreBindingFixture(revision uint64) fileservice.Config {
	c := serviceConfigFixture(revision)
	c.Shares.Volumes = []shareconfig.Volume{
		{ID: "bulk", FilesystemUUID: "11111111-2222-3333-4444-555555555555"},
		{ID: "other", FilesystemUUID: "66666666-7777-8888-9999-aaaaaaaaaaaa"},
	}
	c.Shares.Users = []shareconfig.User{{ID: "reader", Name: "reader"}}
	c.Shares.Shares = []shareconfig.Share{{ID: "books", Name: "Books", VolumeID: "bulk", RelativePath: "books", Grants: []shareconfig.Grant{{UserID: "reader", Access: "ro"}}}}
	for i, path := range []string{"books", "music"} {
		id := []string{"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"}[i]
		c.NFS.Exports = append(c.NFS.Exports, nfsconfig.Export{ID: id, VolumeID: "bulk", RelativePath: path,
			Clients: []nfsconfig.Client{{Network: "192.0.2.10/32", Access: "ro", Squash: "all", AnonymousUID: 65534, AnonymousGID: 65534, Security: "sys"}}})
	}
	return c
}

func TestServiceRestoreRetainedNFSSource(t *testing.T) {
	for _, tc := range []struct {
		name, expected string
		change         func(*fileservice.Config)
		absent         bool
		status         int
	}{
		{name: "root", change: func(c *fileservice.Config) { c.NFS.Exports[0].RelativePath = "other-books" }, status: 422},
		{name: "volume", change: func(c *fileservice.Config) { c.NFS.Exports[0].VolumeID = "other" }, status: 422},
		{name: "filesystem", change: func(c *fileservice.Config) {
			c.Shares.Volumes[0].FilesystemUUID = "cccccccc-dddd-eeee-ffff-000000000000"
		}, status: 422},
		{name: "client", change: func(c *fileservice.Config) { c.NFS.Exports[0].Clients[0].Access = "rw" }, status: 200},
		{name: "addition", change: func(c *fileservice.Config) {
			e := c.NFS.Exports[0]
			e.ID, e.RelativePath = "cccccccc-dddd-eeee-ffff-000000000000", "notes"
			c.NFS.Exports = append(c.NFS.Exports, e)
		}, status: 200},
		{name: "removal", change: func(c *fileservice.Config) { c.NFS.Exports = c.NFS.Exports[1:] }, status: 200},
		{name: "reorder", change: func(c *fileservice.Config) { slices.Reverse(c.Shares.Volumes); slices.Reverse(c.NFS.Exports) }, status: 200},
		{name: "initial", expected: "0", absent: true, status: 200},
		{name: "stale", expected: "6", change: func(c *fileservice.Config) { c.NFS.Exports[0].RelativePath = "other-books" }, status: 409},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auth, cookie := newTestAuth(t)
			baseline, candidate := restoreBindingFixture(7), restoreBindingFixture(71)
			current := &baseline
			if tc.absent {
				current = nil
			}
			if tc.change != nil {
				tc.change(&candidate)
			}
			before, err := json.Marshal(current)
			if err != nil {
				t.Fatal(err)
			}
			data, err := fileservice.EncodeBackup(candidate)
			if err != nil {
				t.Fatal("candidate must be valid independently", err)
			}
			originalData := bytes.Clone(data)
			loads := 0
			backend := &serviceStateBackend{load: func() (*fileservice.Config, error) { loads++; return current, nil },
				commit: func(uint64, fileservice.Config) error { t.Fatal("preview committed"); return nil }}
			expected := tc.expected
			if expected == "" {
				expected = "7"
			}
			r := restoreRequest(t, auth, cookie, expected)
			r.Body, r.ContentLength = io.NopCloser(bytes.NewReader(data)), int64(len(data))
			w := httptest.NewRecorder()
			newHandlerWithServiceState(nil, nil, nil, nil, auth, nil, backend).ServeHTTP(w, r)
			after, err := json.Marshal(current)
			if w.Code != tc.status || loads != 1 || err != nil || !bytes.Equal(before, after) || !bytes.Equal(data, originalData) {
				t.Fatalf("status=%d want%d loads=%d; preview must preserve inputs", w.Code, tc.status, loads)
			}
			if tc.status != 200 {
				var refusal map[string]string
				if json.Unmarshal(w.Body.Bytes(), &refusal) != nil || len(refusal) != 1 || refusal["error"] == "" {
					t.Fatal("refusal returned candidate or preview data")
				}
				return
			}
			var reply struct {
				Configuration fileservice.Config  `json:"configuration"`
				Preview       fileservice.Preview `json:"preview"`
				Saved         bool                `json:"saved"`
				Applied       bool                `json:"applied"`
			}
			revision, _ := strconv.ParseUint(expected, 10, 64)
			if json.Unmarshal(w.Body.Bytes(), &reply) != nil || reply.Configuration.Revision != revision+1 ||
				reply.Saved || reply.Applied || reply.Preview.Applied || reply.Preview.Persisted || reply.Preview.ActivationAvailable ||
				!reflect.DeepEqual(reply.Configuration.NFS.Exports, candidate.NFS.Exports) ||
				!reflect.DeepEqual(reply.Configuration.Shares.Volumes, candidate.Shares.Volumes) {
				t.Fatal("allowed preview changed definitions or claimed persistence/activation")
			}
		})
	}
}
