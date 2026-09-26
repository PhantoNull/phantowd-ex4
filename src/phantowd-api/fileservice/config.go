// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package fileservice

import (
	"encoding/json"
	"errors"
	"io"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/nfsconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

const ConfigFormat = "phantowd-file-service-config"
const MaxConfigBytes = MaxInputBytes + 256

var ErrConfig = errors.New("invalid combined file-service configuration")

// Config is one atomic desired-policy revision. Its component revisions and
// NFS volume binding must all equal Revision, even for an NFS-only edit. This
// makes stale cross-protocol combinations unrepresentable in committed state.
// It contains no credentials, observed device paths or activation authority.
type Config struct {
	Format        string             `json:"format"`
	SchemaVersion int                `json:"schema_version"`
	Revision      uint64             `json:"revision"`
	Shares        shareconfig.Config `json:"shares"`
	NFS           nfsconfig.Policy   `json:"nfs"`
}

// DecodeConfig is distinct from the unversioned proposal envelope. There is
// no implicit conversion of an existing shares.json or external NFS file.
func DecodeConfig(input io.Reader) (Config, error) {
	data, err := io.ReadAll(io.LimitReader(input, int64(MaxConfigBytes)+1))
	if err != nil {
		return Config{}, ErrConfig
	}
	fields, err := decodeEnvelope(data, MaxConfigBytes, "format", "schema_version", "revision", "shares", "nfs")
	if err != nil {
		return Config{}, ErrConfig
	}
	var c Config
	if json.Unmarshal(fields["format"], &c.Format) != nil ||
		json.Unmarshal(fields["schema_version"], &c.SchemaVersion) != nil ||
		json.Unmarshal(fields["revision"], &c.Revision) != nil {
		return Config{}, ErrConfig
	}
	c.Shares, c.NFS, err = decodePolicies(fields)
	if err != nil || c.Validate() != nil {
		return Config{}, ErrConfig
	}
	return c, nil
}

func (c Config) Validate() error {
	if c.Format != ConfigFormat || c.SchemaVersion != 1 || c.Revision == 0 ||
		c.Shares.Revision != c.Revision || c.NFS.Revision != c.Revision || c.NFS.VolumeRevision != c.Revision {
		return ErrConfig
	}
	if _, err := Build(c.Shares, c.NFS); err != nil {
		return ErrConfig
	}
	return nil
}
