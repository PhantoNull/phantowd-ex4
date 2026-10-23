// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package fileservice

import (
	"bytes"
	"encoding/json"
	"slices"
	"testing"
)

func TestRetainedNFSBindingsRejectSourceChanges(t *testing.T) {
	for _, kind := range []string{"root", "volume", "filesystem"} {
		t.Run(kind, func(t *testing.T) {
			base, next := configFixture(1), configFixture(2)
			switch kind {
			case "root":
				next.NFS.Exports[0].RelativePath = "other"
			case "volume":
				next.Shares.Volumes[0].ID, next.Shares.Shares[0].VolumeID, next.NFS.Exports[0].VolumeID = "other", "other", "other"
			case "filesystem":
				next.Shares.Volumes[0].FilesystemUUID = "66666666-7777-8888-9999-aaaaaaaaaaaa"
			}
			if base.Validate() != nil || next.Validate() != nil {
				t.Fatal("binding-change fixture must be valid on its own")
			}
			if err := ValidateRetainedNFSBindings(base, next); err != ErrConfig {
				t.Fatal("retained export source changed", err)
			}
		})
	}
}

func TestRetainedNFSBindingsRejectInvalidDocuments(t *testing.T) {
	bad := configFixture(1)
	bad.NFS.Exports[0].Clients = nil
	for _, invalid := range []Config{{}, bad} {
		if ValidateRetainedNFSBindings(invalid, configFixture(2)) != ErrConfig || ValidateRetainedNFSBindings(configFixture(1), invalid) != ErrConfig {
			t.Fatal("missing or malformed current/next policy accepted")
		}
	}
}

func TestRetainedNFSBindingsAllowEditsWithoutMutationOrHistoricalLedger(t *testing.T) {
	for _, kind := range []string{"unchanged", "clients", "new-id", "addition", "removal", "reorder", "deleted-id-reuse"} {
		t.Run(kind, func(t *testing.T) {
			base, next := configFixture(1), configFixture(2)
			switch kind {
			case "clients":
				client := &next.NFS.Exports[0].Clients[0]
				client.Network, client.Access, client.Squash, client.Security = "198.51.100.1/32", "ro", "root", "krb5p"
				client.AnonymousUID, client.AnonymousGID = 65534, 65534
			case "new-id", "addition":
				export := next.NFS.Exports[0]
				export.ID, export.RelativePath = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff", "other"
				if kind == "addition" {
					next.NFS.Exports = append(next.NFS.Exports, export)
				} else {
					next.NFS.Exports[0] = export
				}
			case "removal":
				next.NFS.Exports = next.NFS.Exports[:0]
			case "reorder":
				for _, c := range []*Config{&base, &next} {
					volume, export := c.Shares.Volumes[0], c.NFS.Exports[0]
					volume.ID, volume.FilesystemUUID = "other", "66666666-7777-8888-9999-aaaaaaaaaaaa"
					export.ID, export.VolumeID = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff", "other"
					c.Shares.Volumes, c.NFS.Exports = append(c.Shares.Volumes, volume), append(c.NFS.Exports, export)
				}
				slices.Reverse(next.Shares.Volumes)
				slices.Reverse(next.NFS.Exports)
			case "deleted-id-reuse":
				base, next = configFixture(2), configFixture(3)
				base.NFS.Exports = base.NFS.Exports[:0] // The deletion has erased the prior binding; there is no ledger.
				next.NFS.Exports[0].RelativePath = "other"
			}
			before, _ := json.Marshal([]Config{base, next})
			if err := ValidateRetainedNFSBindings(base, next); err != nil {
				t.Fatal("allowed desired edit refused", err)
			}
			after, _ := json.Marshal([]Config{base, next})
			if !bytes.Equal(before, after) {
				t.Fatal("binding comparison mutated supplied documents")
			}
		})
	}
}
