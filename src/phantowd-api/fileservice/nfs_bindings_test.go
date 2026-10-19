// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package fileservice

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/nfsconfig"
)

func TestRetainedNFSBindingsRejectRootFilesystemAndLogicalVolumeChanges(t *testing.T) {
	for _, kind := range []string{"root", "filesystem", "logical-volume"} {
		t.Run(kind, func(t *testing.T) {
			base, next := configFixture(1), configFixture(2)
			switch kind {
			case "root":
				next.NFS.Exports[0].RelativePath = "unrelated"
			case "filesystem":
				next.Shares.Volumes[0].FilesystemUUID = "66666666-7777-8888-9999-aaaaaaaaaaaa"
			case "logical-volume":
				next.Shares.Volumes[0].ID = "other"
				next.Shares.Shares[0].VolumeID = "other"
				next.NFS.Exports[0].VolumeID = "other"
			}
			if next.Validate() != nil {
				t.Fatal("fixture must be valid in isolation")
			}
			if err := ValidateRetainedNFSBindings(base, next); !errors.Is(err, ErrConfig) {
				t.Fatal("retained export identity redirected", err)
			}
		})
	}
}

func TestRetainedNFSBindingsAllowClientEditsAdditionRemovalAndNewIdentity(t *testing.T) {
	for _, kind := range []string{"unchanged", "clients", "addition", "removal", "new-id"} {
		t.Run(kind, func(t *testing.T) {
			base, next := configFixture(1), configFixture(2)
			switch kind {
			case "clients":
				client := &next.NFS.Exports[0].Clients[0]
				client.Network, client.Access, client.Squash = "198.51.100.7/32", "ro", "root"
				client.AnonymousUID, client.AnonymousGID, client.Security = 65534, 65534, "krb5p"
			case "addition":
				added := next.NFS.Exports[0]
				added.ID, added.RelativePath = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff", "other"
				next.NFS.Exports = append(next.NFS.Exports, added)
			case "removal":
				next.NFS.Exports = []nfsconfig.Export{}
			case "new-id":
				next.NFS.Exports[0].ID, next.NFS.Exports[0].RelativePath = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff", "other"
			}
			before, _ := json.Marshal([]Config{base, next})
			if err := ValidateRetainedNFSBindings(base, next); err != nil {
				t.Fatal("ordinary desired edit refused", err)
			}
			after, _ := json.Marshal([]Config{base, next})
			if !bytes.Equal(before, after) {
				t.Fatal("binding comparison changed caller-owned policy")
			}
		})
	}
}

func TestRetainedNFSBindingsDoNotValidateMissingOrMalformedConfigurations(t *testing.T) {
	for _, which := range []string{"missing-base", "missing-next", "malformed-base", "malformed-next"} {
		base, next := configFixture(1), configFixture(2)
		switch which {
		case "missing-base":
			base = Config{}
		case "missing-next":
			next = Config{}
		case "malformed-base":
			base.NFS.Exports[0].VolumeID = "missing"
		case "malformed-next":
			next.NFS.Exports[0].Clients = nil
		}
		if err := ValidateRetainedNFSBindings(base, next); !errors.Is(err, ErrConfig) {
			t.Fatal("incomplete configuration accepted", which, err)
		}
	}
}
