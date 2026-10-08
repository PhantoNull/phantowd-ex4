// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package smbconfig

import (
	"reflect"
	"strings"
	"testing"
)

func TestIsolatedCandidateKeepsGrantsButNeverUsesVolumeAnchors(t *testing.T) {
	config := fixture()
	preview, err := BuildIsolated(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"[Books & Comics]", "path = /shares/library\n",
		"valid users = alice bob\n", "read list = alice\n", "write list = bob\n",
		"guest ok = no", "read only = yes", "wide links = no", "follow symlinks = no",
	} {
		if !strings.Contains(preview.Sections, required) {
			t.Fatalf("isolated candidate lost %q", required)
		}
	}
	if strings.Contains(preview.Sections, VolumeRoot) || strings.Contains(preview.Sections, "eve") ||
		len(preview.Shares) != 1 || preview.Shares[0].Path != "/shares/library" ||
		len(preview.Volumes) != 1 || preview.Volumes[0].MountPath != VolumeRoot+"/books" {
		t.Fatal("isolated candidate widened access or lost the original source requirement")
	}
	ordinary, err := Build(config)
	if err != nil || !strings.Contains(ordinary.Sections, "path = "+VolumeRoot+"/books/Library/Technical Books") ||
		config.Shares[0].RelativePath != "Library/Technical Books" {
		t.Fatal("isolated rendering changed ordinary previews or caller policy")
	}
}

func TestIsolatedCandidateRefusesWholeVolumeWithoutChangingOrdinaryPreview(t *testing.T) {
	config := fixture()
	config.Shares[0].RelativePath = "."
	if _, err := Build(config); err != nil {
		t.Fatal("ordinary desired-policy preview changed:", err)
	}
	preview, err := BuildIsolated(config)
	if err == nil || !reflect.DeepEqual(preview, Preview{}) {
		t.Fatal("whole-volume request produced a usable isolated candidate")
	}
}
