// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package iscsipolicy validates desired iSCSI configuration. It grants no
// authority to open backing objects, resolve credentials or configure a target.
package iscsipolicy

import (
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"math"
	"strings"
	"unicode/utf8"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/configjson"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

const (
	Format        = "phantowd-iscsi-policy"
	SchemaVersion = 1
	MaxInputBytes = 128 << 10
	MaxTargets    = 16
	MaxBackings   = 64
	MaxLUNs       = 16 // Per target; total also bounded by MaxBackings.
	MaxInitiators = 32 // Per target.
)

var ErrInvalid = errors.New("invalid desired iSCSI policy")

type TargetID string
type LUNID string
type BackingID string
type SecretRef string

type Policy struct {
	Format         string    `json:"format"`
	SchemaVersion  int       `json:"schema_version"`
	Revision       uint64    `json:"revision"`
	VolumeRevision uint64    `json:"volume_revision"`
	Backings       []Backing `json:"backings"`
	Targets        []Target  `json:"targets"`
}

type Backing struct {
	ID            BackingID            `json:"id"`
	VolumeID      shareconfig.VolumeID `json:"volume_id"`
	RelativePath  string               `json:"relative_path"`
	CapacityBytes uint64               `json:"capacity_bytes"`
	BlockSize     uint16               `json:"block_size"`
	Allocation    string               `json:"allocation"`
}

type Target struct {
	ID         TargetID    `json:"id"`
	Name       string      `json:"name"`
	State      string      `json:"state"`
	LUNs       []LUN       `json:"luns"`
	Initiators []Initiator `json:"initiators"`
}

type LUN struct {
	ID        LUNID     `json:"id"`
	Number    uint16    `json:"number"`
	BackingID BackingID `json:"backing_id"`
	Access    string    `json:"access"`
}

type Initiator struct {
	Name           string         `json:"name"`
	Authentication Authentication `json:"authentication"`
	Grants         []Grant        `json:"grants"`
}

type Authentication struct {
	Mode               string    `json:"mode"`
	InitiatorUser      string    `json:"initiator_user"`
	InitiatorSecretRef SecretRef `json:"initiator_secret_ref"`
	TargetUser         string    `json:"target_user,omitempty"`
	TargetSecretRef    SecretRef `json:"target_secret_ref,omitempty"`
}

type Grant struct {
	LUNID  LUNID  `json:"lun_id"`
	Access string `json:"access"`
}

var fields = map[string]bool{
	"format": true, "schema_version": true, "revision": true, "volume_revision": true,
	"backings": true, "targets": true, "id": true, "volume_id": true,
	"relative_path": true, "capacity_bytes": true, "block_size": true,
	"allocation": true, "name": true, "state": true, "luns": true,
	"number": true, "backing_id": true, "access": true, "initiators": true,
	"authentication": true, "mode": true, "initiator_user": true,
	"initiator_secret_ref": true, "target_user": true, "target_secret_ref": true,
	"grants": true, "lun_id": true,
}

// Private wire wrappers distinguish a missing number from the valid number 0.
// The shadowed fields retain strict standard struct decoding at every level.
type wirePolicy struct {
	Policy
	Targets []wireTarget `json:"targets"`
}
type wireTarget struct {
	Target
	LUNs []wireLUN `json:"luns"`
}
type wireLUN struct {
	LUN
	Number *uint16 `json:"number"`
}

// Decode returns no partial policy and never echoes untrusted input or I/O.
func Decode(input io.Reader, volumes shareconfig.Config) (Policy, error) {
	var w wirePolicy
	if input == nil || configjson.Decode(input, &w, MaxInputBytes, 9, fields) != nil || w.Targets == nil {
		return Policy{}, ErrInvalid
	}
	p := w.Policy
	p.Targets = make([]Target, len(w.Targets))
	for i, target := range w.Targets {
		p.Targets[i] = target.Target
		if target.LUNs == nil {
			return Policy{}, ErrInvalid
		}
		p.Targets[i].LUNs = make([]LUN, len(target.LUNs))
		for j, lun := range target.LUNs {
			if lun.Number == nil {
				return Policy{}, ErrInvalid
			}
			p.Targets[i].LUNs[j] = lun.LUN
			p.Targets[i].LUNs[j].Number = *lun.Number
		}
	}
	if p.Validate(volumes) != nil {
		return Policy{}, ErrInvalid
	}
	return p, nil
}

// Validate checks only desired relationships. Callers retain the inputs and
// must not mutate them concurrently; revisions do not establish runtime trust.
func (p Policy) Validate(volumes shareconfig.Config) error {
	if volumes.Validate() != nil || p.Format != Format || p.SchemaVersion != SchemaVersion ||
		p.Revision == 0 || p.VolumeRevision != volumes.Revision ||
		p.Backings == nil || p.Targets == nil || len(p.Backings) > MaxBackings || len(p.Targets) > MaxTargets {
		return ErrInvalid
	}
	known := make(map[shareconfig.VolumeID]bool, len(volumes.Volumes))
	for _, v := range volumes.Volumes {
		known[v.ID] = true
	}
	backings := make(map[BackingID]bool, len(p.Backings))
	for i, b := range p.Backings {
		if !identifier(string(b.ID)) || backings[b.ID] || !known[b.VolumeID] || !filePath(b.RelativePath) ||
			(b.BlockSize != 512 && b.BlockSize != 4096) || b.CapacityBytes < uint64(b.BlockSize) ||
			b.CapacityBytes > math.MaxInt64 || b.CapacityBytes%uint64(b.BlockSize) != 0 ||
			(b.Allocation != "preallocated" && b.Allocation != "sparse") {
			return ErrInvalid
		}
		for _, old := range p.Backings[:i] {
			if old.VolumeID == b.VolumeID && pathOverlap(old.RelativePath, b.RelativePath) {
				return ErrInvalid
			}
		}
		backings[b.ID] = true
	}
	targetIDs, names := map[TargetID]bool{}, map[string]bool{}
	lunIDs, usedBackings, secrets := map[LUNID]bool{}, map[BackingID]bool{}, map[SecretRef]bool{}
	for _, target := range p.Targets {
		if !identifier(string(target.ID)) || targetIDs[target.ID] || !iqn(target.Name) || names[target.Name] ||
			(target.State != "disabled" && target.State != "enabled") || len(target.LUNs) == 0 || len(target.LUNs) > MaxLUNs ||
			len(target.Initiators) == 0 || len(target.Initiators) > MaxInitiators {
			return ErrInvalid
		}
		targetIDs[target.ID], names[target.Name] = true, true
		localLUNs, numbers := map[LUNID]string{}, map[uint16]bool{}
		for _, lun := range target.LUNs {
			if !identifier(string(lun.ID)) || lunIDs[lun.ID] || numbers[lun.Number] ||
				!backings[lun.BackingID] || usedBackings[lun.BackingID] || !access(lun.Access) {
				return ErrInvalid
			}
			lunIDs[lun.ID], numbers[lun.Number], usedBackings[lun.BackingID] = true, true, true
			localLUNs[lun.ID] = lun.Access
		}
		initiators := map[string]bool{}
		for _, peer := range target.Initiators {
			if !iqn(peer.Name) || initiators[peer.Name] || !authentication(peer.Authentication, secrets) ||
				len(peer.Grants) == 0 || len(peer.Grants) > MaxLUNs {
				return ErrInvalid
			}
			initiators[peer.Name] = true
			granted := map[LUNID]bool{}
			for _, g := range peer.Grants {
				mode, exists := localLUNs[g.LUNID]
				if !exists || granted[g.LUNID] || !access(g.Access) || (mode == "ro" && g.Access != "ro") {
					return ErrInvalid
				}
				granted[g.LUNID] = true
			}
		}
	}
	if len(usedBackings) != len(backings) {
		return ErrInvalid
	}
	data, err := json.Marshal(p)
	if err != nil || len(data) > MaxInputBytes {
		return ErrInvalid
	}
	return nil
}

func authentication(a Authentication, used map[SecretRef]bool) bool {
	if (a.Mode != "chap" && a.Mode != "mutual-chap") || !username(a.InitiatorUser) ||
		!identifier(string(a.InitiatorSecretRef)) || used[a.InitiatorSecretRef] {
		return false
	}
	if a.Mode == "chap" {
		if a.TargetUser != "" || a.TargetSecretRef != "" {
			return false
		}
	} else if !username(a.TargetUser) || !identifier(string(a.TargetSecretRef)) ||
		a.TargetSecretRef == a.InitiatorSecretRef || used[a.TargetSecretRef] {
		return false
	}
	used[a.InitiatorSecretRef] = true
	if a.TargetSecretRef != "" {
		used[a.TargetSecretRef] = true
	}
	return true
}

func access(s string) bool { return s == "ro" || s == "rw" }

func identifier(s string) bool {
	if len(s) == 0 || len(s) > 64 || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

func username(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("._-@", c)) {
			return false
		}
	}
	return true
}

func filePath(s string) bool {
	if s == "." || len(s) == 0 || len(s) > 1024 || !utf8.ValidString(s) || !fs.ValidPath(s) || strings.ContainsAny(s, "\\:") {
		return false
	}
	for _, c := range s {
		if c < 32 || c == 127 {
			return false
		}
	}
	return true
}

func pathOverlap(a, b string) bool {
	return a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}

// iqn intentionally accepts a documented canonical ASCII profile, not all
// RFC/stringprep names. Domain ownership/uniqueness cannot be checked here.
func iqn(s string) bool {
	if len(s) < 14 || len(s) > 223 || !strings.HasPrefix(s, "iqn.") || s[8] != '-' || s[11] != '.' {
		return false
	}
	for _, c := range s[4:8] {
		if c < '0' || c > '9' {
			return false
		}
	}
	if s[4:8] == "0000" || s[9] < '0' || s[9] > '1' || s[10] < '0' || s[10] > '9' || s[9:11] < "01" || s[9:11] > "12" {
		return false
	}
	domain, suffix, colon := strings.Cut(s[12:], ":")
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if len(l) == 0 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	if colon {
		if suffix == "" {
			return false
		}
		for _, c := range suffix {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.ContainsRune(".-:", c)) {
				return false
			}
		}
	}
	return true
}
