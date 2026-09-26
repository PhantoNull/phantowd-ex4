// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package nfsconfig validates and previews desired NFS policy. It never calls
// exportfs, mounts filesystems or changes a running server.
package nfsconfig

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"net/netip"
	"path"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/configjson"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

const (
	Format        = "phantowd-nfs-policy"
	MaxInputBytes = 256 << 10
	MaxExports    = 128
	MaxClients    = 64
	VolumeRoot    = shareconfig.VolumeMountRoot
)

// VolumeRevision binds the proposal to the exact shared volume configuration.
// Standalone proposals have a separate policy revision. The combined
// fileservice.Config binds all component revisions to one atomic transaction.
type Policy struct {
	Format         string   `json:"format"`
	SchemaVersion  int      `json:"schema_version"`
	Revision       uint64   `json:"revision"`
	VolumeRevision uint64   `json:"volume_revision"`
	Exports        []Export `json:"exports"`
}

type Export struct {
	// ID is a stable, unique UUID used as the NFS fsid, not the volume UUID.
	ID           string   `json:"id"`
	VolumeID     string   `json:"volume_id"`
	RelativePath string   `json:"relative_path"`
	Clients      []Client `json:"clients"`
}

// NFS clients and numeric UNIX identities are not Samba account grants.
type Client struct {
	Network      string `json:"network"`
	Access       string `json:"access"`
	Squash       string `json:"squash"`
	AnonymousUID uint32 `json:"anonymous_uid"`
	AnonymousGID uint32 `json:"anonymous_gid"`
	Security     string `json:"security"`
}

var fields = map[string]bool{
	"format": true, "schema_version": true, "revision": true, "volume_revision": true,
	"exports": true, "id": true, "volume_id": true, "relative_path": true,
	"clients": true, "network": true, "access": true, "squash": true,
	"anonymous_uid": true, "anonymous_gid": true, "security": true,
}

func Decode(input io.Reader, volumes shareconfig.Config) (Policy, error) {
	var p Policy
	if configjson.Decode(input, &p, MaxInputBytes, 8, fields) != nil {
		return Policy{}, errors.New("invalid NFS policy JSON")
	}
	if err := p.Validate(volumes); err != nil {
		return Policy{}, err
	}
	return p, nil
}

func (p Policy) Validate(volumes shareconfig.Config) error {
	if volumes.Validate() != nil {
		return errors.New("invalid shared volume configuration")
	}
	if p.Format != Format || p.SchemaVersion != 1 || p.Revision == 0 || p.VolumeRevision != volumes.Revision {
		return errors.New("unsupported or stale NFS policy")
	}
	if p.Exports == nil || len(p.Exports) > MaxExports {
		return errors.New("missing or excessive NFS exports")
	}
	known := make(map[string]bool, len(volumes.Volumes))
	for _, volume := range volumes.Volumes {
		known[volume.ID] = true
	}
	ids := map[string]bool{}
	for i, export := range p.Exports {
		if !uuid(export.ID) || ids[export.ID] || !known[export.VolumeID] || !relativePath(export.RelativePath) ||
			len(export.Clients) == 0 || len(export.Clients) > MaxClients {
			return fmt.Errorf("invalid NFS export at index %d", i)
		}
		ids[export.ID] = true
		for j := 0; j < i; j++ {
			other := p.Exports[j]
			if other.VolumeID == export.VolumeID && overlaps(path.Join("/", other.RelativePath), path.Join("/", export.RelativePath)) {
				return errors.New("overlapping NFS export paths are unsupported")
			}
		}
		prefixes := []netip.Prefix{}
		for j, client := range export.Clients {
			prefix, err := netip.ParsePrefix(client.Network)
			if err != nil || !validNetwork(prefix, client.Network) || (client.Access != "ro" && client.Access != "rw") ||
				(client.Squash != "root" && client.Squash != "all") || !anonymousID(client.AnonymousUID) || !anonymousID(client.AnonymousGID) ||
				(client.Security != "sys" && client.Security != "krb5" && client.Security != "krb5i" && client.Security != "krb5p") {
				return fmt.Errorf("invalid NFS client at export %d, index %d", i, j)
			}
			for _, other := range prefixes {
				if prefix.Overlaps(other) {
					return errors.New("overlapping NFS client networks are unsupported")
				}
			}
			prefixes = append(prefixes, prefix)
		}
	}
	data, err := json.Marshal(p)
	if err != nil || len(data) > MaxInputBytes {
		return errors.New("NFS policy exceeds size limit")
	}
	return nil
}

func anonymousID(id uint32) bool { return id != 0 && id != math.MaxUint32 }

func uuid(s string) bool {
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' || strings.ToLower(s) != s {
		return false
	}
	raw := strings.ReplaceAll(s, "-", "")
	if len(raw) != 32 || raw == strings.Repeat("0", 32) {
		return false
	}
	_, err := hex.DecodeString(raw)
	return err == nil
}

func relativePath(s string) bool {
	if len(s) == 0 || len(s) > 1024 || !utf8.ValidString(s) || !fs.ValidPath(s) || strings.Contains(s, "\\") {
		return false
	}
	for _, c := range s {
		if c < 32 || c == 127 {
			return false
		}
	}
	return true
}

func validNetwork(p netip.Prefix, spelling string) bool {
	if !p.IsValid() || p.Bits() == 0 || p != p.Masked() || p.String() != spelling || p.Addr().Is4In6() || p.Addr().IsUnspecified() {
		return false
	}
	for _, forbidden := range []string{"224.0.0.0/4", "240.0.0.0/4", "ff00::/8"} {
		if p.Overlaps(netip.MustParsePrefix(forbidden)) {
			return false
		}
	}
	return true
}

func overlaps(a, b string) bool {
	return a == b || a == "/" || b == "/" || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}

type Preview struct {
	SchemaVersion    int             `json:"schema_version"`
	Revision         uint64          `json:"revision"`
	VolumeRevision   uint64          `json:"volume_revision"`
	Exports          []ExportPreview `json:"exports"`
	Table            string          `json:"exports_table"`
	UsesAUTH_SYS     bool            `json:"uses_auth_sys"`
	RequiresKerberos bool            `json:"requires_kerberos"`
}

type ExportPreview struct {
	ID             string   `json:"id"`
	VolumeID       string   `json:"volume_id"`
	FilesystemUUID string   `json:"filesystem_uuid"`
	MountPath      string   `json:"mount_path"`
	Path           string   `json:"path"`
	Clients        []Client `json:"clients"`
}

// Build produces candidate exports text, not an installed or authorized
// export. Mountpoint guards cannot prove the correct filesystem is mounted.
func Build(p Policy, volumes shareconfig.Config) (Preview, error) {
	if err := p.Validate(volumes); err != nil {
		return Preview{}, err
	}
	known := make(map[string]string, len(volumes.Volumes))
	for _, volume := range volumes.Volumes {
		known[volume.ID] = volume.FilesystemUUID
	}
	preview := Preview{SchemaVersion: 1, Revision: p.Revision, VolumeRevision: p.VolumeRevision, Exports: []ExportPreview{}}
	for _, export := range p.Exports {
		mount := path.Join(VolumeRoot, known[export.VolumeID])
		clients := slices.Clone(export.Clients)
		slices.SortFunc(clients, func(a, b Client) int { return strings.Compare(a.Network, b.Network) })
		preview.Exports = append(preview.Exports, ExportPreview{export.ID, export.VolumeID, known[export.VolumeID], mount,
			path.Join(mount, export.RelativePath), clients})
	}
	slices.SortFunc(preview.Exports, func(a, b ExportPreview) int { return strings.Compare(a.ID, b.ID) })
	var table strings.Builder
	table.WriteString("# PhantoWD candidate exports; verify identities, containment and credentials before activation.\n")
	for _, export := range preview.Exports {
		table.WriteString(escapePath(export.Path))
		for _, client := range export.Clients {
			squash := "root_squash"
			if client.Squash == "all" {
				squash += ",all_squash"
			}
			subtree := "subtree_check"
			if export.Path == export.MountPath {
				subtree = "no_subtree_check"
			}
			fmt.Fprintf(&table, " %s(%s,sync,secure,%s,%s,nocrossmnt,sec=%s,anonuid=%d,anongid=%d,fsid=%s,mountpoint=%s)",
				client.Network, client.Access, squash, subtree, client.Security, client.AnonymousUID, client.AnonymousGID, export.ID, export.MountPath)
			preview.UsesAUTH_SYS = preview.UsesAUTH_SYS || client.Security == "sys"
			preview.RequiresKerberos = preview.RequiresKerberos || client.Security != "sys"
		}
		table.WriteByte('\n')
	}
	preview.Table = table.String()
	return preview, nil
}

func escapePath(s string) string {
	var out strings.Builder
	for _, b := range []byte(s) {
		if b == ' ' || b == '"' || b == '#' || b == '\\' {
			fmt.Fprintf(&out, "\\%03o", b)
		} else {
			out.WriteByte(b)
		}
	}
	return out.String()
}
