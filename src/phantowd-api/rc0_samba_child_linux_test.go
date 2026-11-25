// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import "testing"

func TestDecodeRC0SambaLaunch(t *testing.T) {
	const prefix = `{"format":"phantowd-rc0-samba-launch-v1","shares":`
	roles, err := decodeRC0SambaLaunch([]byte(prefix + `[{"id":"rw-share","read_only":false},{"id":"ro-share","read_only":true}]}`))
	if err != nil || len(roles) != 2 || roles[0].ID != "rw-share" || *roles[0].ReadOnly || roles[1].ID != "ro-share" || !*roles[1].ReadOnly {
		t.Fatalf("valid ordered declaration: roles=%v err=%v", roles, err)
	}
	for name, shares := range map[string]string{
		"empty":      `[]`,
		"path":       `[{"id":"../private","read_only":true}]`,
		"missing":    `[{"id":"share"}]`,
		"null":       `[{"id":"share","read_only":null}]`,
		"duplicate":  `[{"id":"share","read_only":true},{"id":"share","read_only":false}]`,
		"repeated":   `[{"id":"share","read_only":true,"read_only":false}]`,
		"extra":      `[{"id":"share","read_only":true,"path":"/"}]`,
		"case alias": `[{"id":"share","READ_ONLY":true}]`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeRC0SambaLaunch([]byte(prefix + shares + `}`)); err == nil {
				t.Fatal("unsafe declaration accepted")
			}
		})
	}
}
