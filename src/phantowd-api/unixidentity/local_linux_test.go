// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package unixidentity

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func localFixture(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "etc")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{"passwd": basePasswd + accountRow, "group": baseGroups + groupRow, "nsswitch.conf": localNSS} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestReadLocalVerifiedSources(t *testing.T) {
	dir := localFixture(t)
	s, err := ReadLocal(dir, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	status, err := s.Assess(desired)
	if err != nil || status != Observed {
		t.Fatal(status, err)
	}
	if _, err := ReadLocal("relative", uint32(os.Getuid())); !errors.Is(err, ErrUnsafe) {
		t.Fatal(err)
	}
	if _, err := ReadLocal(dir+"/.", uint32(os.Getuid())); !errors.Is(err, ErrUnsafe) {
		t.Fatal(err)
	}
	if _, err := ReadLocal(dir, uint32(os.Getuid())+1); !errors.Is(err, ErrUnsafe) {
		t.Fatal(err)
	}
}

func TestReadLocalUnsafeObjects(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "fifo", "directory", "writable", "missing", "empty", "oversize", "root-writable", "root-symlink", "parent-symlink", "nss"} {
		t.Run(kind, func(t *testing.T) {
			dir := localFixture(t)
			path := filepath.Join(dir, "passwd")
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			switch kind {
			case "symlink":
				must(os.Rename(path, path+"-source"))
				must(os.Symlink("passwd-source", path))
			case "hardlink":
				must(os.Link(path, path+"-alias"))
			case "fifo":
				must(os.Remove(path))
				must(unix.Mkfifo(path, 0600))
			case "directory":
				must(os.Remove(path))
				must(os.Mkdir(path, 0700))
			case "writable":
				must(os.Chmod(path, 0666))
			case "missing":
				must(os.Remove(path))
			case "empty":
				must(os.Truncate(path, 0))
			case "oversize":
				must(os.Truncate(path, MaxFileBytes+1))
			case "root-writable":
				must(os.Chmod(dir, 0777))
			case "root-symlink":
				must(os.Symlink(dir, dir+"-alias"))
				dir += "-alias"
			case "parent-symlink":
				parent := filepath.Dir(dir)
				alias := filepath.Join(t.TempDir(), "alias")
				must(os.Symlink(parent, alias))
				dir = filepath.Join(alias, "etc")
			case "nss":
				must(os.WriteFile(filepath.Join(dir, "nsswitch.conf"), []byte("passwd: ldap\ngroup: files\n"), 0644))
			}
			s, err := ReadLocal(dir, uint32(os.Getuid()))
			if err == nil || s.valid {
				t.Fatal("unsafe observation escaped", err)
			}
			if kind == "nss" && !errors.Is(err, ErrNSS) {
				t.Fatal(err)
			}
		})
	}
}

func TestReadLocalRechecksNamesAndMetadata(t *testing.T) {
	for _, kind := range []string{"rewrite", "rename", "chmod", "nss-rewrite", "group-remove", "directory-replace"} {
		t.Run(kind, func(t *testing.T) {
			dir := localFixture(t)
			path := filepath.Join(dir, "passwd")
			hook := func() {
				must := func(err error) {
					t.Helper()
					if err != nil {
						t.Fatal(err)
					}
				}
				switch kind {
				case "rewrite":
					must(os.WriteFile(path, []byte(basePasswd), 0644))
				case "rename":
					must(os.Rename(path, path+"-old"))
					must(os.WriteFile(path, []byte(basePasswd+accountRow), 0644))
				case "chmod":
					must(os.Chmod(path, 0600))
				case "nss-rewrite":
					must(os.WriteFile(filepath.Join(dir, "nsswitch.conf"), []byte("passwd: ldap\ngroup: files\n"), 0644))
				case "group-remove":
					must(os.Remove(filepath.Join(dir, "group")))
				case "directory-replace":
					must(os.Rename(dir, dir+"-old"))
					must(os.Mkdir(dir, 0700))
				}
			}
			s, err := readLocal(dir, uint32(os.Getuid()), hook)
			if !errors.Is(err, ErrChanged) || s.valid {
				t.Fatal("changed source accepted", err)
			}
		})
	}
}
