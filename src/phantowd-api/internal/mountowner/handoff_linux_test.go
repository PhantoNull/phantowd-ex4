//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package mountowner

import (
	"reflect"
	"testing"
)

func TestNormalizeServiceSharesUsesOnlyDisjointDeclaredSubdirectories(t *testing.T) {
	available := map[string]bool{"volume-a": true, "volume-b": true}
	input := []ServiceShare{
		{ID: "comics", VolumeID: "volume-a", RelativePath: "media/comics", ReadOnly: true},
		{ID: "books", VolumeID: "volume-a", RelativePath: "media/books"},
	}
	got, ok := normalizeServiceShares(input, available)
	if !ok {
		t.Fatal("valid disjoint share roots were rejected")
	}
	if want := []ServiceShare{input[1], input[0]}; !reflect.DeepEqual(got, want) {
		t.Fatalf("shares were not returned in stable ID order: got %#v, want %#v", got, want)
	}
	if !reflect.DeepEqual(input[0], ServiceShare{ID: "comics", VolumeID: "volume-a", RelativePath: "media/comics", ReadOnly: true}) {
		t.Fatal("normalization mutated the caller's share slice")
	}
}

func TestNormalizeServiceSharesRejectsInvalidRootsAndAliases(t *testing.T) {
	base := ServiceShare{ID: "media", VolumeID: "volume-a", RelativePath: "media/books"}
	tests := []struct {
		name   string
		shares []ServiceShare
	}{
		{name: "whole volume", shares: []ServiceShare{{ID: "media", VolumeID: "volume-a", RelativePath: "."}}},
		{name: "parent traversal", shares: []ServiceShare{{ID: "media", VolumeID: "volume-a", RelativePath: "../other"}}},
		{name: "nested traversal", shares: []ServiceShare{{ID: "media", VolumeID: "volume-a", RelativePath: "media/../other"}}},
		{name: "absolute", shares: []ServiceShare{{ID: "media", VolumeID: "volume-a", RelativePath: "/media"}}},
		{name: "backslash", shares: []ServiceShare{{ID: "media", VolumeID: "volume-a", RelativePath: `media\\books`}}},
		{name: "duplicate share ID", shares: []ServiceShare{base, {ID: "media", VolumeID: "volume-b", RelativePath: "media/books"}}},
		{name: "same path", shares: []ServiceShare{base, {ID: "books", VolumeID: "volume-a", RelativePath: "media/books"}}},
		{name: "ancestor overlap", shares: []ServiceShare{base, {ID: "nested", VolumeID: "volume-a", RelativePath: "media/books/series"}}},
		{name: "unknown volume", shares: []ServiceShare{{ID: "media", VolumeID: "missing", RelativePath: "media"}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, ok := normalizeServiceShares(test.shares, map[string]bool{"volume-a": true, "volume-b": true}); ok {
				t.Fatal("invalid share-root request was accepted")
			}
		})
	}
}
