// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package naspolicy defines one coherent desired SMB/NFS/iSCSI revision.
// It grants no storage, identity, credential, process or activation authority.
package naspolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/configjson"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsipolicy"
)

const (
	Format        = "phantowd-nas-service-config"
	SchemaVersion = 1
	MaxInputBytes = fileservice.MaxConfigBytes + iscsipolicy.MaxInputBytes + 256
)

var ErrInvalid = errors.New("invalid combined NAS service configuration")

type Config struct {
	Format        string             `json:"format"`
	SchemaVersion int                `json:"schema_version"`
	Revision      uint64             `json:"revision"`
	FileServices  fileservice.Config `json:"file_services"`
	ISCSI         iscsipolicy.Policy `json:"iscsi"`
}

// Decode never promotes partial/missing/legacy policy or resolves SecretRefs.
// Child decoders retain their own strict schemas and independent byte limits.
func Decode(input io.Reader) (Config, error) {
	if input == nil {
		return Config{}, ErrInvalid
	}
	data, err := io.ReadAll(io.LimitReader(input, MaxInputBytes+1))
	if err != nil {
		return Config{}, ErrInvalid
	}
	fields, err := configjson.DecodeEnvelope(data, MaxInputBytes, 12,
		"format", "schema_version", "revision", "file_services", "iscsi")
	if err != nil {
		return Config{}, ErrInvalid
	}
	var c Config
	if json.Unmarshal(fields["format"], &c.Format) != nil ||
		json.Unmarshal(fields["schema_version"], &c.SchemaVersion) != nil ||
		json.Unmarshal(fields["revision"], &c.Revision) != nil {
		return Config{}, ErrInvalid
	}
	c.FileServices, err = fileservice.DecodeConfig(bytes.NewReader(fields["file_services"]))
	if err != nil {
		return Config{}, ErrInvalid
	}
	c.ISCSI, err = iscsipolicy.Decode(bytes.NewReader(fields["iscsi"]), c.FileServices.Shares)
	if err != nil || c.Validate() != nil {
		return Config{}, ErrInvalid
	}
	return c, nil
}

// All seven component revision/binding values equal the one desired revision.
// Registry/device generations remain separate; equality does not mint trust.
// Inputs remain caller-owned and must not be changed concurrently.
func (c Config) Validate() error {
	if c.Format != Format || c.SchemaVersion != SchemaVersion || c.Revision == 0 ||
		c.FileServices.Revision != c.Revision || c.ISCSI.Revision != c.Revision ||
		c.FileServices.Validate() != nil || c.ISCSI.Validate(c.FileServices.Shares) != nil {
		return ErrInvalid
	}
	// A direct Go value must also fit each nested decoder, not only the larger
	// combined limit, or a successful commit could be unreadable on reopen.
	fileData, err := json.Marshal(c.FileServices)
	if err != nil || len(fileData) > fileservice.MaxConfigBytes {
		return ErrInvalid
	}
	iscsiData, err := json.Marshal(c.ISCSI)
	if err != nil || len(iscsiData) > iscsipolicy.MaxInputBytes {
		return ErrInvalid
	}
	return nil
}
