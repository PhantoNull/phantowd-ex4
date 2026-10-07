//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package mountowner

import (
	"reflect"
	"slices"
	"testing"
)

func TestSharePinRequestMatchingBindsCompleteDeclarationWithoutAliasing(t *testing.T) {
	actual := []ServiceShare{
		{ID: "readonly", VolumeID: "bulk", RelativePath: "books", ReadOnly: true},
		{ID: "writable", VolumeID: "bulk", RelativePath: "downloads"},
	}
	reversed := []ServiceShare{actual[1], actual[0]}
	before := slices.Clone(reversed)
	if !sameDeclaredRootsQEMU(reversed, actual) || !reflect.DeepEqual(reversed, before) {
		t.Fatal("equivalent declaration was refused or reordered in caller memory")
	}
	for name, mutate := range map[string]func([]ServiceShare) []ServiceShare{
		"absent":    func([]ServiceShare) []ServiceShare { return nil },
		"missing":   func(r []ServiceShare) []ServiceShare { return r[:1] },
		"extra":     func(r []ServiceShare) []ServiceShare { return append(r, ServiceShare{ID: "extra"}) },
		"ID":        func(r []ServiceShare) []ServiceShare { r[0].ID = "different"; return r },
		"volume":    func(r []ServiceShare) []ServiceShare { r[0].VolumeID = "other"; return r },
		"path":      func(r []ServiceShare) []ServiceShare { r[0].RelativePath = "replacement"; return r },
		"RO":        func(r []ServiceShare) []ServiceShare { r[0].ReadOnly = false; return r },
		"duplicate": func(r []ServiceShare) []ServiceShare { r[1] = r[0]; return r },
	} {
		t.Run(name, func(t *testing.T) {
			if sameDeclaredRootsQEMU(mutate(slices.Clone(actual)), actual) {
				t.Fatal("different or incomplete root requests matched original pins")
			}
		})
	}
	if sameDeclaredRootsQEMU(nil, nil) || sameDeclaredRootsQEMU([]ServiceShare{{}}, []ServiceShare{{}}) {
		t.Fatal("empty/invalid declaration matched")
	}
}
