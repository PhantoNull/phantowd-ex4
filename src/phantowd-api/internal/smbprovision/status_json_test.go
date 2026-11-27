// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package smbprovision

import (
	"strings"
	"testing"
)

func TestSambaActivityRequiresCompleteReport(t *testing.T) {
	const header = `{"version":"4.22.11","smb_conf":"/etc/samba/smb.conf",`
	const sections = `"sessions":{},"tcons":{},"open_files":{}`
	for _, tc := range []struct {
		name, data string
		want       Activity
		bad        bool
	}{
		{"empty", header + sections + `,"phantowd_complete":true}`, Activity{Complete: true}, false},
		{"legacy", header + sections + `}`, Activity{}, false},
		{"active", header + `"sessions":{"a":{}},"tcons":{"b":{}},"open_files":{"c":{},"d":{}},"phantowd_complete":true}`,
			Activity{Sessions: 1, Trees: 1, OpenFiles: 2, Complete: true}, false},
		{"missing locks", header + `"sessions":{},"tcons":{},"phantowd_complete":true}`, Activity{}, true},
		{"null locks", header + `"sessions":{},"tcons":{},"open_files":null,"phantowd_complete":true}`, Activity{}, true},
		{"duplicate", header + sections + `,"phantowd_complete":false,"phantowd_complete":true}`, Activity{}, true},
		{"trailing", header + sections + `,"phantowd_complete":true}{}`, Activity{}, true},
		{"wrong marker type", header + sections + `,"phantowd_complete":"true"}`, Activity{}, true},
		{"wrong config", strings.Replace(header, "/etc/samba/smb.conf", "/etc/smb.conf", 1) + sections + `}`, Activity{}, true},
		{"unknown version", strings.Replace(header, "4.22.11", "4.23.0", 1) + sections + `}`, Activity{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseActivity([]byte(tc.data))
			if (err != nil) != tc.bad || got != tc.want {
				t.Fatalf("census = %+v, error = %v", got, err)
			}
		})
	}
}
