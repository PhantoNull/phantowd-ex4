// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package shareconfig defines desired share policy independently of observed
// devices and mount paths. It performs no I/O beyond reading supplied JSON.
package shareconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"
	"unicode/utf8"
)

const (
	Format        = "phantowd-share-config"
	SchemaVersion = 1
	MaxInputBytes = 256 << 10
	MaxVolumes    = 16
	MaxUsers      = 128
	MaxShares     = 128
)

// Config is a desired-policy document, not a claim that its volumes are present
// or compatible. Revision is reserved for optimistic concurrency in the store.
type Config struct {
	Format        string   `json:"format"`
	SchemaVersion int      `json:"schema_version"`
	Revision      uint64   `json:"revision"`
	Volumes       []Volume `json:"volumes"`
	Users         []User   `json:"users"`
	Shares        []Share  `json:"shares"`
}

// Volume binds a project ID to the filesystem identity expected by a future
// resolver. The resolver must separately refuse absent or duplicate identities.
type Volume struct {
	ID             string `json:"id"`
	FilesystemUUID string `json:"filesystem_uuid"`
}

// User references a future file-service account. It contains no credentials and
// is separate from the development dashboard administrator account.
type User struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Share struct {
	ID           string  `json:"id"`
	Name         string  `json:"name"`
	VolumeID     string  `json:"volume_id"`
	RelativePath string  `json:"relative_path"`
	Grants       []Grant `json:"grants"`
}

type Grant struct {
	UserID string `json:"user_id"`
	Access string `json:"access"`
}

// Decode rejects oversized input, duplicate/unknown/missing fields, nulls and
// invalid relationships. Errors intentionally omit caller-supplied values.
func Decode(input io.Reader) (Config, error) {
	data, err := io.ReadAll(io.LimitReader(input, MaxInputBytes+1))
	if err != nil || len(data) > MaxInputBytes || !utf8.Valid(data) {
		return Config{}, errors.New("cannot read bounded UTF-8 share configuration")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := scanValue(decoder, 0); err != nil {
		return Config{}, errors.New("invalid share configuration JSON")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return Config{}, errors.New("trailing share configuration JSON")
	}
	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return Config{}, errors.New("invalid share configuration fields")
	}
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

// Validate also protects callers constructing a Config directly. It establishes
// policy consistency only; filesystem containment and account provisioning
// require validation by the eventual runtime resolver and service layer.
func (c Config) Validate() error {
	if c.Format != Format || c.SchemaVersion != SchemaVersion || c.Revision == 0 {
		return errors.New("unsupported share configuration format, schema or revision")
	}
	if c.Volumes == nil || c.Users == nil || c.Shares == nil ||
		len(c.Volumes) > MaxVolumes || len(c.Users) > MaxUsers || len(c.Shares) > MaxShares {
		return errors.New("missing or excessive configuration collections")
	}
	volumes, uuids := map[string]bool{}, map[string]bool{}
	for i, volume := range c.Volumes {
		if !identifier(volume.ID) || volumes[volume.ID] || !filesystemUUID(volume.FilesystemUUID) || uuids[volume.FilesystemUUID] {
			return fmt.Errorf("invalid or duplicate volume at index %d", i)
		}
		volumes[volume.ID], uuids[volume.FilesystemUUID] = true, true
	}
	users, names := map[string]bool{}, map[string]bool{}
	for i, user := range c.Users {
		if !identifier(user.ID) || users[user.ID] || !accountName(user.Name) || names[user.Name] {
			return fmt.Errorf("invalid or duplicate user at index %d", i)
		}
		users[user.ID], names[user.Name] = true, true
	}
	shares, shareNames := map[string]bool{}, map[string]bool{}
	for i, share := range c.Shares {
		foldedName := strings.ToLower(share.Name)
		if !identifier(share.ID) || shares[share.ID] || !shareName(share.Name) || shareNames[foldedName] ||
			!volumes[share.VolumeID] || !relativePath(share.RelativePath) || len(share.Grants) == 0 || len(share.Grants) > MaxUsers {
			return fmt.Errorf("invalid share at index %d", i)
		}
		grantees := map[string]bool{}
		for j, grant := range share.Grants {
			if !users[grant.UserID] || grantees[grant.UserID] || (grant.Access != "ro" && grant.Access != "rw") {
				return fmt.Errorf("invalid grant at share %d, index %d", i, j)
			}
			grantees[grant.UserID] = true
		}
		shares[share.ID], shareNames[foldedName] = true, true
	}
	return nil
}

func identifier(s string) bool {
	if len(s) == 0 || len(s) > 64 || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for _, ch := range s {
		if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
			return false
		}
	}
	return true
}

func accountName(s string) bool {
	if len(s) == 0 || len(s) > 32 || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for _, ch := range s {
		if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_') {
			return false
		}
	}
	return s != "root" && s != "nobody" && s != "phantowd"
}

func shareName(s string) bool {
	if len(s) == 0 || len(s) > 80 || strings.TrimSpace(s) != s || strings.HasSuffix(s, ".") {
		return false
	}
	switch strings.ToLower(s) {
	case ".", "..", "global", "homes", "printers", "print$", "ipc$", "admin$":
		return false
	}
	for _, ch := range s {
		if ch < 32 || ch > 126 || strings.ContainsRune("[]/\\:;=\"<>|?*", ch) {
			return false
		}
	}
	return true
}

func relativePath(s string) bool {
	if len(s) == 0 || len(s) > 1024 || !utf8.ValidString(s) || !fs.ValidPath(s) || strings.ContainsAny(s, "\\:") {
		return false
	}
	for _, ch := range s {
		if ch < 32 || ch == 127 {
			return false
		}
	}
	return true
}

func filesystemUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	nonzero := false
	for i, ch := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if ch != '-' {
				return false
			}
			continue
		}
		if !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f') {
			return false
		}
		nonzero = nonzero || ch != '0'
	}
	return nonzero
}

// Field spelling is exact, unlike encoding/json's case-insensitive matching.
var fields = map[string]bool{
	"format": true, "schema_version": true, "revision": true, "volumes": true,
	"users": true, "shares": true, "id": true, "filesystem_uuid": true,
	"name": true, "volume_id": true, "relative_path": true, "grants": true,
	"user_id": true, "access": true,
}

func scanValue(d *json.Decoder, depth int) error {
	if depth > 8 {
		return errors.New("excessive nesting")
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	if token == nil {
		return errors.New("null is not supported")
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			keyToken, err := d.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok || seen[key] || !fields[key] {
				return errors.New("duplicate or unknown field")
			}
			seen[key] = true
			if err := scanValue(d, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for d.More() {
			if err := scanValue(d, depth+1); err != nil {
				return err
			}
		}
	default:
		return errors.New("unexpected delimiter")
	}
	_, err = d.Token()
	return err
}
