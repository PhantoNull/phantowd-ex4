// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package fileservice

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/configjson"
)

const BackupFormat = "phantowd-file-service-backup"
const MaxBackupBytes = MaxConfigBytes + 256

var ErrBackup = errors.New("invalid file-service backup")

// Backup contains desired policy, including private names/networks/UUIDs, not
// passwords, identities, data, a disk backup or service activation authority.
type Backup struct {
	Format        string `json:"format"`
	SchemaVersion int    `json:"schema_version"`
	Configuration Config `json:"configuration"`
}

// EncodeBackup validates exact bounded policy before producing a versioned file.
func EncodeBackup(c Config) ([]byte, error) {
	if c.Validate() != nil {
		return nil, ErrBackup
	}
	encoded, err := json.Marshal(c)
	if err != nil {
		return nil, ErrBackup
	}
	validated, err := DecodeConfig(bytes.NewReader(encoded))
	if err != nil {
		return nil, ErrBackup
	}
	data, err := json.Marshal(Backup{Format: BackupFormat, SchemaVersion: 1, Configuration: validated})
	if err != nil || len(data) > MaxBackupBytes {
		return nil, ErrBackup
	}
	return data, nil
}

// RestoreCandidate strictly validates ORIGINAL uploaded bytes before rebasing
// every policy revision. The expected revision is a caller's CAS prerequisite,
// not a trusted current-store observation. This function neither saves nor
// imports users, resolves volumes, starts services, or changes filesystem data.
func RestoreCandidate(data []byte, expected uint64) (Config, error) {
	fail := func() (Config, error) { return Config{}, ErrBackup }
	if expected == math.MaxUint64 {
		return fail()
	}
	fields, err := configjson.DecodeEnvelope(data, MaxBackupBytes, 12, "format", "schema_version", "configuration")
	if err != nil {
		return fail()
	}
	var format string
	var version int
	if json.Unmarshal(fields["format"], &format) != nil || format != BackupFormat ||
		json.Unmarshal(fields["schema_version"], &version) != nil || version != 1 {
		return fail()
	}
	c, err := DecodeConfig(bytes.NewReader(fields["configuration"]))
	if err != nil {
		return fail()
	}
	c.Revision = expected + 1
	c.Shares.Revision = c.Revision
	c.NFS.Revision = c.Revision
	c.NFS.VolumeRevision = c.Revision
	encoded, err := json.Marshal(c)
	if err != nil {
		return fail()
	}
	// Revision growth must not waive the original component/combined size limits.
	c, err = DecodeConfig(bytes.NewReader(encoded))
	if err != nil {
		return fail()
	}
	return c, nil
}
