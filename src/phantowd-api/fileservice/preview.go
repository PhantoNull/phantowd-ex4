// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package fileservice builds a non-executable, combined desired-policy preview.
// It has no storage, filesystem, process, credential or network capability.
package fileservice

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/nfsconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/smbconfig"
)

const MaxInputBytes = shareconfig.MaxInputBytes + nfsconfig.MaxInputBytes + 256

var (
	ErrEnvelope = errors.New("invalid file-service preview envelope")
	ErrShares   = errors.New("invalid shared volume/share policy")
	ErrSamba    = errors.New("unsupported Samba preview policy")
	ErrNFS      = errors.New("invalid NFS preview policy")
)

type Preview struct {
	SchemaVersion       int               `json:"schema_version"`
	Scope               string            `json:"scope"`
	Persisted           bool              `json:"persisted"`
	Applied             bool              `json:"applied"`
	RuntimeValidated    bool              `json:"runtime_validated"`
	ActivationAvailable bool              `json:"activation_available"`
	Requirements        []string          `json:"requirements"`
	Samba               smbconfig.Preview `json:"samba"`
	NFS                 nfsconfig.Preview `json:"nfs"`
}

// Decode accepts exactly {"shares": <shareconfig>, "nfs": <nfsconfig>}.
// Nested raw documents go through their own bounded strict decoders; parsing
// the envelope must not silently collapse duplicate or case-aliased keys.
func Decode(data []byte) (Preview, error) {
	if len(data) > MaxInputBytes {
		return Preview{}, ErrEnvelope
	}
	d := json.NewDecoder(bytes.NewReader(data))
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return Preview{}, ErrEnvelope
	}
	fields := map[string]json.RawMessage{}
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok || (key != "shares" && key != "nfs") || fields[key] != nil {
			return Preview{}, ErrEnvelope
		}
		var raw json.RawMessage
		if err := d.Decode(&raw); err != nil || bytes.Equal(raw, []byte("null")) {
			return Preview{}, ErrEnvelope
		}
		fields[key] = raw
	}
	closing, err := d.Token()
	if err != nil || closing != json.Delim('}') || len(fields) != 2 {
		return Preview{}, ErrEnvelope
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return Preview{}, ErrEnvelope
	}
	shares, err := shareconfig.Decode(bytes.NewReader(fields["shares"]))
	if err != nil {
		return Preview{}, ErrShares
	}
	nfs, err := nfsconfig.Decode(bytes.NewReader(fields["nfs"]), shares)
	if err != nil {
		return Preview{}, ErrNFS
	}
	sambaPreview, err := smbconfig.Build(shares)
	if err != nil {
		return Preview{}, ErrSamba
	}
	nfsPreview, err := nfsconfig.Build(nfs, shares)
	if err != nil {
		return Preview{}, ErrNFS
	}
	requirements := []string{"runtime_volume_identity", "path_and_mount_containment", "unix_accounts_and_effective_access", "durable_configuration", "service_activation_lifecycle"}
	if len(shares.Shares) != 0 && len(nfs.Exports) != 0 {
		requirements = append(requirements, "cross_protocol_access_review")
	}
	if nfsPreview.UsesAUTH_SYS {
		requirements = append(requirements, "auth_sys_network_trust")
	}
	if nfsPreview.RequiresKerberos {
		requirements = append(requirements, "kerberos_provisioning")
	}
	return Preview{SchemaVersion: 1, Scope: "desired-policy-only", Requirements: requirements, Samba: sambaPreview, NFS: nfsPreview}, nil
}
