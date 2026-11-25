// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package naspolicy

import (
	"bytes"
	"encoding/json"
	"math"
	"reflect"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/configjson"
)

const BackupFormat = "phantowd-nas-policy-backup"
const MaxBackupBytes = MaxInputBytes + 256

// RestoreCandidate decodes original backup bytes and rebases all desired-policy
// revisions. Expected is a caller CAS prerequisite, not a store observation.
// No identities, credentials, backing data or service authority are imported.
func RestoreCandidate(data []byte, expected uint64) (Config, error) {
	if expected == math.MaxUint64 {
		return Config{}, ErrInvalid
	}
	c, _, err := decodeBackup(data)
	if err != nil {
		return Config{}, err
	}
	setRevision(&c, expected+1)
	encoded, err := json.Marshal(c)
	if err != nil {
		return Config{}, ErrInvalid
	}
	// Revision digit growth must still fit the complete and nested decoder limits.
	return Decode(bytes.NewReader(encoded))
}

// SavedConfirmation extracts the exact canonical configuration in a backup
// captured after a managed save. Preserve revision-one provisioning bytes
// separately, since their original formatting need not be canonical.
func SavedConfirmation(data []byte, revision uint64) ([]byte, error) {
	if revision < 2 {
		return nil, ErrInvalid
	}
	c, policy, err := decodeBackup(data)
	if err != nil || c.Revision != revision {
		return nil, ErrInvalid
	}
	encoded, err := json.Marshal(c)
	if err != nil || !bytes.Equal(policy, encoded) {
		return nil, ErrInvalid
	}
	return policy, nil
}

func decodeBackup(data []byte) (Config, []byte, error) {
	fields, err := configjson.DecodeEnvelope(data, MaxBackupBytes, 12, "format", "schema_version", "configuration")
	if err != nil {
		return Config{}, nil, ErrInvalid
	}
	var format string
	var version int
	if json.Unmarshal(fields["format"], &format) != nil || format != BackupFormat ||
		json.Unmarshal(fields["schema_version"], &version) != nil || version != 1 {
		return Config{}, nil, ErrInvalid
	}
	c, err := Decode(bytes.NewReader(fields["configuration"]))
	if err != nil {
		return Config{}, nil, ErrInvalid
	}
	return c, fields["configuration"], nil
}

// SameDefinitions ignores only coherent revisions, never uint64 values or array
// order. A match observes current definitions; it is not a save acknowledgement.
func SameDefinitions(a, b Config) bool {
	if a.Validate() != nil || b.Validate() != nil {
		return false
	}
	setRevision(&a, b.Revision)
	return reflect.DeepEqual(a, b)
}

func setRevision(c *Config, r uint64) {
	c.Revision, c.FileServices.Revision, c.FileServices.Shares.Revision = r, r, r
	c.FileServices.NFS.Revision, c.FileServices.NFS.VolumeRevision = r, r
	c.ISCSI.Revision, c.ISCSI.VolumeRevision = r, r
}
