// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package smbconfig

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

func fixture() shareconfig.Config {
	return shareconfig.Config{Format: shareconfig.Format, SchemaVersion: 1, Revision: 7,
		Volumes: []shareconfig.Volume{{ID: "books", FilesystemUUID: "11111111-2222-3333-4444-555555555555"}},
		Users:   []shareconfig.User{{ID: "reader", Name: "alice"}, {ID: "writer", Name: "bob"}, {ID: "denied", Name: "eve"}},
		Shares: []shareconfig.Share{{ID: "library", Name: "Books & Comics", VolumeID: "books", RelativePath: "Library/Technical Books",
			Grants: []shareconfig.Grant{{UserID: "reader", Access: "ro"}, {UserID: "writer", Access: "rw"}}}}}
}

func TestPreviewAccessAndIdentity(t *testing.T) {
	c := fixture()
	before, _ := json.Marshal(c)
	p, err := Build(c)
	if err != nil {
		t.Fatal(err)
	}
	if p.Revision != 7 || len(p.Volumes) != 1 || p.Volumes[0].FilesystemUUID != c.Volumes[0].FilesystemUUID {
		t.Fatal("lost identity/revision")
	}
	for _, want := range []string{"[Books & Comics]", "path = /srv/phantowd/volumes/11111111-2222-3333-4444-555555555555/Library/Technical Books",
		"valid users = alice bob\n", "read list = alice\n", "write list = bob\n", "guest ok = no", "read only = yes", "wide links = no", "follow symlinks = no"} {
		if !strings.Contains(p.Sections, want) {
			t.Fatalf("missing %q", want)
		}
	}
	if strings.Contains(p.Sections, "eve") || strings.Contains(p.Sections, "force user") || strings.Contains(p.Sections, "force group") {
		t.Fatal("broadened access")
	}
	if !reflect.DeepEqual(p.Shares[0].ReadOnly, []string{"alice"}) || !reflect.DeepEqual(p.Shares[0].ReadWrite, []string{"bob"}) {
		t.Fatal("wrong access matrix")
	}
	after, _ := json.Marshal(c)
	if !bytes.Equal(before, after) {
		t.Fatal("mutated caller config")
	}
}

func TestReorderingAndUnusedVolume(t *testing.T) {
	c := fixture()
	c.Volumes = append(c.Volumes, shareconfig.Volume{ID: "unused", FilesystemUUID: "22222222-2222-3333-4444-555555555555"})
	one, err := Build(c)
	if err != nil {
		t.Fatal(err)
	}
	c.Users[0], c.Users[1] = c.Users[1], c.Users[0]
	c.Volumes[0], c.Volumes[1] = c.Volumes[1], c.Volumes[0]
	c.Shares[0].Grants[0], c.Shares[0].Grants[1] = c.Shares[0].Grants[1], c.Shares[0].Grants[0]
	two, err := Build(c)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(one, two) || len(two.Volumes) != 1 {
		t.Fatal("unstable preview or unnecessary mount requirement")
	}
}

func TestReadOnlyAndWriteOnlyGrantLists(t *testing.T) {
	for _, access := range []string{"ro", "rw"} {
		c := fixture()
		c.Shares[0].Grants = []shareconfig.Grant{{UserID: "reader", Access: access}}
		p, err := Build(c)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(p.Sections, "read only = yes\n") {
			t.Fatal("default write access")
		}
		if access == "ro" && !strings.Contains(p.Sections, "write list = \n") {
			t.Fatal("write list must be empty")
		}
		if access == "rw" && !strings.Contains(p.Sections, "read list = \n") {
			t.Fatal("read-only list must be empty")
		}
	}
}

func TestRejectInterpolationAndInjection(t *testing.T) {
	for _, unsafe := range []string{"%U", "books/%u", "books\"", "books#tail", "books;tail", "books=value", "books/[global]", "books/ trailing", "books/trailing ", "../outside", "/etc", "books\ninclude = /tmp/evil"} {
		c := fixture()
		c.Shares[0].RelativePath = unsafe
		if _, err := Build(c); err == nil {
			t.Errorf("accepted unsafe path %q", unsafe)
		}
	}
	for _, unsafe := range []string{"%U", "Books#comment", "[global]", "Books\n[global]"} {
		c := fixture()
		c.Shares[0].Name = unsafe
		if _, err := Build(c); err == nil {
			t.Errorf("accepted unsafe name %q", unsafe)
		}
	}
}

func TestRejectOverlappingPaths(t *testing.T) {
	for _, relative := range []string{"Library", "Library/Technical Books", "Library/Technical Books/sub", "."} {
		c := fixture()
		second := c.Shares[0]
		second.ID = "second"
		second.Name = "Second"
		second.RelativePath = relative
		c.Shares = append(c.Shares, second)
		if _, err := Build(c); err == nil {
			t.Errorf("accepted overlap %q", relative)
		}
	}
	c := fixture()
	second := c.Shares[0]
	second.ID = "second"
	second.Name = "Second"
	second.RelativePath += "-other"
	c.Shares = append(c.Shares, second)
	if _, err := Build(c); err != nil {
		t.Fatal("rejected non-overlapping sibling", err)
	}
}

func TestEmptyAndRootPolicy(t *testing.T) {
	c := shareconfig.Config{Format: shareconfig.Format, SchemaVersion: 1, Revision: 1,
		Volumes: []shareconfig.Volume{}, Users: []shareconfig.User{}, Shares: []shareconfig.Share{}}
	p, err := Build(c)
	if err != nil || len(p.Shares) != 0 || len(p.Volumes) != 0 || strings.Contains(p.Sections, "[global]") {
		t.Fatal("empty policy", err)
	}
	c = fixture()
	c.Shares[0].RelativePath = "."
	p, err = Build(c)
	if err != nil || p.Shares[0].Path != p.Volumes[0].MountPath {
		t.Fatal("explicit root policy", err)
	}
}

func FuzzPreview(f *testing.F) {
	seed, _ := json.Marshal(fixture())
	f.Add(seed)
	f.Add([]byte(`{"format":"phantowd-share-config","schema_version":1,"revision":1,"volumes":[],"users":[],"shares":[]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := shareconfig.Decode(bytes.NewReader(data))
		if err != nil {
			return
		}
		p, err := Build(c)
		if err != nil {
			return
		}
		if len(p.Shares) != len(c.Shares) || strings.Contains(p.Sections, "%") {
			t.Fatal("unsafe rendering")
		}
		if strings.Count(p.Sections, "\n[") != len(c.Shares) {
			t.Fatal("injected section")
		}
		again, err := Build(c)
		if err != nil || !reflect.DeepEqual(p, again) {
			t.Fatal("nondeterministic rendering")
		}
	})
}
