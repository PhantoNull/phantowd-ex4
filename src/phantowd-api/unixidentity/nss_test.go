// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package unixidentity

import (
	"strings"
	"testing"
)

const localNSS = "passwd: files\ngroup: files\n"

func TestFilesOnlyNSS(t *testing.T) {
	for _, test := range []struct {
		input string
		want  bool
	}{
		{localNSS, true}, {"# comment\npasswd:\tfiles # comment\ngroup: files\nhosts: files dns\n", true},
		{localNSS + "initgroups: files\n", true},
		{"", false}, {"passwd: files\n", false}, {"group: files\n", false},
		{localNSS + "initgroups: ldap\n", false}, {localNSS + "initgroups: files [SUCCESS=merge] ldap\n", false},
		{localNSS + "passwd: ldap\n", false}, {localNSS + "GROUP: files\n", false},
		{strings.Replace(localNSS, "files", "files systemd", 1), false},
		{strings.Replace(localNSS, "files", "compat", 1), false},
		{strings.Replace(localNSS, "files", "files [NOTFOUND=return]", 1), false},
		{localNSS + "broken\n", false}, {localNSS + ": files\n", false},
		{localNSS + "initgroups: files\ninitgroups: files\n", false},
		{localNSS + "\x00", false}, {localNSS + "\r", false}, {localNSS + "\xff", false},
		{localNSS + strings.Repeat("#", MaxLineBytes+1), false}, {strings.Repeat("\n", MaxNSSBytes+1), false},
	} {
		if got := FilesOnlyNSS([]byte(test.input)); got != test.want {
			t.Fatalf("NSS accepted=%v want=%v", got, test.want)
		}
	}
}

func FuzzFilesOnlyNSS(f *testing.F) {
	f.Add([]byte(localNSS))
	f.Add([]byte(localNSS + "initgroups: files\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if !FilesOnlyNSS(data) {
			return
		}
		for _, extra := range []string{"passwd: ldap\n", "group: compat\n", "initgroups: winbind\n"} {
			if FilesOnlyNSS(append(append([]byte{}, data...), []byte("\n"+extra)...)) {
				t.Fatal("unsafe identity override accepted")
			}
		}
	})
}
