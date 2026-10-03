// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package volumeregistry observes explicitly provisioned registry claims.
// It does not register volumes, grant leases or authorize storage operations.
package volumeregistry

import (
	"errors"
	"io"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/configjson"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

const (
	Format        = "phantowd-volume-registry"
	SchemaVersion = 1
	MaxInputBytes = 64 << 10
)

var ErrObservation = errors.New("volume registry observation unavailable")

// Document is data, not trusted provenance or durable adoption. IDs must have
// been assigned explicitly. This first schema records UUID expectations only.
type Document struct {
	Format        string               `json:"format"`
	SchemaVersion int                  `json:"schema_version"`
	Revision      uint64               `json:"revision"`
	Volumes       []shareconfig.Volume `json:"volumes"`
}

func (d Document) Validate() error {
	if d.Format != Format || d.SchemaVersion != SchemaVersion {
		return ErrObservation
	}
	// One canonical ID/UUID validator; do not introduce a parallel grammar.
	if err := d.policy().Validate(); err != nil {
		return ErrObservation
	}
	return nil
}

func (d Document) policy() shareconfig.Config {
	return shareconfig.Config{Format: shareconfig.Format, SchemaVersion: shareconfig.SchemaVersion,
		Revision: d.Revision, Volumes: d.Volumes, Users: []shareconfig.User{}, Shares: []shareconfig.Share{}}
}

func Decode(input io.Reader) (Document, error) {
	var d Document
	if input == nil || configjson.Decode(input, &d, MaxInputBytes, 5, fields) != nil || d.Validate() != nil {
		return Document{}, ErrObservation
	}
	return d, nil
}

var fields = map[string]bool{"format": true, "schema_version": true, "revision": true,
	"volumes": true, "id": true, "filesystem_uuid": true}

// Snapshot can only originate from the protected reader, not a decoded
// document. It is immutable across package boundaries and not serializable.
// It proves neither continued freshness nor device uniqueness/qualification.
type Snapshot struct {
	document        Document
	observed        bool
	origin          *readerOrigin
	generation      uint64
	directory, file observationMetadata
}

// Non-zero size ensures distinct Reader allocations have distinct provenance.
// This token retains no descriptor/Reader and grants no storage authority.
type readerOrigin struct{ marker byte }

// Platform-neutral private stamps keep model tests/cross-builds independent of
// Linux syscalls. Only the protected Linux reader populates these observations.
type observationMetadata struct {
	device, inode, links                                         uint64
	mode, uid, gid                                               uint32
	size                                                         int64
	modifiedSeconds, modifiedNanos, changedSeconds, changedNanos int64
}

func (Snapshot) MarshalJSON() ([]byte, error) { return nil, ErrObservation }
func (*Snapshot) UnmarshalJSON([]byte) error  { return ErrObservation }

// Claims returns an independent copy for private point-in-time reconciliation.
// It does not turn its data into a qualification or an activation capability.
func (s Snapshot) Claims() (Document, error) {
	if !s.observed || s.document.Validate() != nil {
		return Document{}, ErrObservation
	}
	d := s.document
	d.Volumes = append([]shareconfig.Volume{}, d.Volumes...)
	return d, nil
}
