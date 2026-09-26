// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package shareconfig

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

const sample = `{"format":"phantowd-share-config","schema_version":1,"revision":1,
"volumes":[{"id":"media","filesystem_uuid":"11111111-2222-3333-4444-555555555555"}],
"users":[{"id":"reader","name":"alice"},{"id":"editor","name":"bob"}],
"shares":[{"id":"books","name":"Books & Comics","volume_id":"media","relative_path":"library/books",
"grants":[{"user_id":"reader","access":"ro"},{"user_id":"editor","access":"rw"}]}]}`

func TestPolicyRoundTrip(t *testing.T) {
	c, err := Decode(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	if c.Shares[0].Grants[0].Access != "ro" || c.Shares[0].Grants[1].Access != "rw" {
		t.Fatal("lost explicit grant policy")
	}
	encoded, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	again, err := Decode(strings.NewReader(string(encoded)))
	if err != nil || !reflect.DeepEqual(c, again) {
		t.Fatalf("round trip: %v", err)
	}
	// References remain stable when account enumeration changes.
	c.Users[0], c.Users[1] = c.Users[1], c.Users[0]
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestRejectAmbiguousOrMalformedJSON(t *testing.T) {
	for name, data := range map[string]string{
		"missing collection":        strings.Replace(sample, `"users":`, `"unexpected":`, 1),
		"missing revision":          strings.Replace(sample, `"revision":1,`, "", 1),
		"case alias":                strings.Replace(sample, `"revision"`, `"Revision"`, 1),
		"duplicate":                 strings.Replace(sample, `"revision":1`, `"revision":1,"revision":2`, 1),
		"escaped duplicate":         strings.Replace(sample, `"revision":1`, `"revision":1,"revi\u0073ion":2`, 1),
		"null access":               strings.Replace(sample, `"access":"ro"`, `"access":null`, 1),
		"missing access":            strings.Replace(sample, `,"access":"ro"`, "", 1),
		"context wrong key":         strings.Replace(sample, `"relative_path"`, `"filesystem_uuid"`, 1),
		"trailing document":         sample + sample,
		"oversize":                  strings.Repeat(" ", MaxInputBytes+1),
		"array instead of document": "[]",
		"invalid UTF8":              sample + string([]byte{255}),
		"null document":             "null",
		"excessive nesting":         strings.Repeat("[", 12) + "0" + strings.Repeat("]", 12),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode(strings.NewReader(data)); err == nil {
				t.Fatal("accepted malformed configuration")
			}
		})
	}
}

func TestRejectUnsafePolicy(t *testing.T) {
	cases := map[string]func(*Config){
		"unknown schema":         func(c *Config) { c.SchemaVersion = 2 },
		"no volumes field":       func(c *Config) { c.Volumes = nil },
		"unknown volume":         func(c *Config) { c.Shares[0].VolumeID = "absent" },
		"unknown user":           func(c *Config) { c.Shares[0].Grants[0].UserID = "absent" },
		"no explicit grants":     func(c *Config) { c.Shares[0].Grants = nil },
		"unsupported permission": func(c *Config) { c.Shares[0].Grants[0].Access = "admin" },
		"contradictory grants":   func(c *Config) { c.Shares[0].Grants[1].UserID = "reader" },
		"duplicate uuid":         func(c *Config) { v := c.Volumes[0]; v.ID = "other"; c.Volumes = append(c.Volumes, v) },
		"zero uuid":              func(c *Config) { c.Volumes[0].FilesystemUUID = "00000000-0000-0000-0000-000000000000" },
		"device path identity":   func(c *Config) { c.Volumes[0].FilesystemUUID = "/dev/sda2" },
		"duplicate share case": func(c *Config) {
			s := c.Shares[0]
			s.ID = "other"
			s.Name = "books & comics"
			c.Shares = append(c.Shares, s)
		},
		"duplicate account":         func(c *Config) { c.Users[1].Name = "alice" },
		"root account":              func(c *Config) { c.Users[0].Name = "root" },
		"path traversal":            func(c *Config) { c.Shares[0].RelativePath = "library/../secrets" },
		"absolute path":             func(c *Config) { c.Shares[0].RelativePath = "/etc" },
		"backslash traversal":       func(c *Config) { c.Shares[0].RelativePath = `library\..\secrets` },
		"control path":              func(c *Config) { c.Shares[0].RelativePath = "line\nbreak" },
		"share directive injection": func(c *Config) { c.Shares[0].Name = "books]\n[global" },
		"reserved share":            func(c *Config) { c.Shares[0].Name = "IPC$" },
		"volume count":              func(c *Config) { c.Volumes = make([]Volume, MaxVolumes+1) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c, err := Decode(strings.NewReader(sample))
			if err != nil {
				t.Fatal(err)
			}
			mutate(&c)
			if err := c.Validate(); err == nil {
				t.Fatal("accepted unsafe or ambiguous policy")
			}
		})
	}
}

func TestEmptyConfigurationAndExplicitVolumeRoot(t *testing.T) {
	if _, err := Decode(strings.NewReader(`{"format":"phantowd-share-config","schema_version":1,"revision":1,"volumes":[],"users":[],"shares":[]}`)); err != nil {
		t.Fatal(err)
	}
	c, err := Decode(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	c.Shares[0].RelativePath = "."
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

func FuzzDecode(f *testing.F) {
	f.Add(sample)
	f.Add(`{"format":"phantowd-share-config"}`)
	f.Fuzz(func(t *testing.T, data string) {
		c, err := Decode(strings.NewReader(data))
		if err != nil {
			return
		}
		if err := c.Validate(); err != nil {
			t.Fatal("decoder accepted invalid policy")
		}
		encoded, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		again, err := Decode(strings.NewReader(string(encoded)))
		if err != nil || !reflect.DeepEqual(c, again) {
			t.Fatalf("accepted configuration cannot round trip: %v", err)
		}
	})
}
