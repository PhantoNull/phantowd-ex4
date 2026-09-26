//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/smbconfig"
)

// Parse a fixed synthetic candidate with the guest's actual Samba parser.
// This starts no daemon and does not touch /etc/samba or any share path.
func exerciseQEMUSMBPreview() error {
	config := shareconfig.Config{Format: shareconfig.Format, SchemaVersion: 1, Revision: 1,
		Volumes: []shareconfig.Volume{{ID: "test-volume", FilesystemUUID: "11111111-2222-3333-4444-555555555555"}},
		Users:   []shareconfig.User{{ID: "reader", Name: "alice"}, {ID: "writer", Name: "bob"}},
		Shares: []shareconfig.Share{{ID: "test-share", Name: "Books & Comics", VolumeID: "test-volume", RelativePath: "Technical Books",
			Grants: []shareconfig.Grant{{UserID: "reader", Access: "ro"}, {UserID: "writer", Access: "rw"}}}}}
	preview, err := smbconfig.Build(config)
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "phantowd-smb-preview-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	name := filepath.Join(dir, "smb.conf")
	const global = "[global]\n    server role = standalone server\n    security = user\n    map to guest = Never\n    interfaces = lo\n    bind interfaces only = yes\n    server min protocol = SMB3_00\n    server max protocol = SMB3_11\n    load printers = no\n    printing = bsd\n    printcap name = /dev/null\n"
	if err := os.WriteFile(name, []byte(global+preview.Sections), 0600); err != nil {
		return err
	}
	for _, parameter := range []struct{ name, want string }{
		{"valid users", "alice bob"}, {"read list", "alice"}, {"write list", "bob"},
		{"read only", "Yes"}, {"guest ok", "No"}, {"wide links", "No"}, {"follow symlinks", "No"},
		{"path", preview.Shares[0].Path},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		command := exec.CommandContext(ctx, "/usr/bin/testparm", "-s", "--section-name=Books & Comics", "--parameter-name="+parameter.name, name)
		output, err := command.Output()
		cancel()
		if err != nil || strings.TrimSpace(string(output)) != parameter.want {
			return errors.New("Samba parser did not preserve generated share policy: " + parameter.name)
		}
	}
	return nil
}
