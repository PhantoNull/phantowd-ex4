// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package rootfsinventory

import (
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Optional local oracle: execute only the pinned host readelf, never target ELF.
// The environment names the existing trusted disposable Buildroot output, not
// an appliance device. Ordinary CI/unit tests do not scan that external tree.
func TestARMAttributesTargetReadelfOracle(t *testing.T) {
	output := os.Getenv("PHANTOWD_ARM_ATTRIBUTES_ORACLE_OUTPUT")
	if output == "" {
		t.Skip("optional read-only pinned Buildroot target oracle")
	}
	root := filepath.Join(output, "target")
	tool := filepath.Join(output, "host", "bin", "arm-buildroot-linux-gnueabi-readelf")
	report, err := Inspect(root)
	if err != nil {
		t.Fatal(err)
	}
	observed, absent, compared := 0, 0, 0
	apiAbsent := false
	for _, file := range report.Files {
		if file.ELF == nil || file.ELF.Machine != "EM_ARM" {
			continue
		}
		attributes := file.ELF.ARMAttributes
		if attributes == nil {
			t.Fatal("missing ARM observation", file.Path)
		}
		command := exec.Command(tool, "-A", filepath.Join(root, filepath.FromSlash(file.Path)))
		command.Env = append(os.Environ(), "LC_ALL=C")
		raw, err := command.Output()
		if err != nil {
			t.Fatal("readelf failed", file.Path, err)
		}
		lines := map[string]bool{}
		for _, line := range strings.Split(string(raw), "\n") {
			lines[strings.TrimSpace(line)] = true
		}
		switch attributes.Status {
		case "absent":
			if strings.Contains(string(raw), "File Attributes") {
				t.Fatal("missed public attributes", file.Path)
			}
			absent++
			if file.Path == "usr/bin/phantowd-api" {
				apiAbsent = true
			}
		case "observed":
			if !lines["File Attributes"] {
				t.Fatal("unexpected file-scope attributes", file.Path)
			}
			observed++
			for _, item := range attributes.FileAttributes {
				var label, value string
				switch item.Tag {
				case 5:
					if item.TextHex == nil {
						t.Fatal("missing CPU name", file.Path)
					}
					decoded, err := hex.DecodeString(*item.TextHex)
					if err != nil {
						t.Fatal(err)
					}
					label, value = "Tag_CPU_name", strconv.Quote(string(decoded))
				case 6:
					label = "Tag_CPU_arch"
					arch := []string{"Pre-v4", "v4", "v4T", "v5T", "v5TE", "v5TEJ", "v6", "v6KZ", "v6T2", "v6K", "v7", "v6-M", "v6S-M", "v7E-M", "v8", "v8-R", "v8-M.baseline", "v8-M.mainline"}
					if item.Integer == nil || *item.Integer >= uint64(len(arch)) {
						t.Fatal("oracle CPU mapping unavailable", file.Path)
					}
					value = arch[*item.Integer]
				case 8:
					label = "Tag_ARM_ISA_use"
					if item.Integer == nil || *item.Integer > 1 {
						t.Fatal("oracle ARM mapping unavailable", file.Path)
					}
					value = []string{"No", "Yes"}[*item.Integer]
				case 9:
					label = "Tag_THUMB_ISA_use"
					if item.Integer == nil || *item.Integer > 2 {
						t.Fatal("oracle Thumb mapping unavailable", file.Path)
					}
					value = []string{"No", "Thumb-1", "Thumb-2"}[*item.Integer]
				default:
					continue
				}
				if !lines[label+": "+value] {
					t.Fatal("independent readelf disagrees", file.Path, label, value, string(raw))
				}
				compared++
			}
		default:
			t.Fatal("current target attributes not observed", file.Path, attributes.Status, attributes.Reason)
		}
	}
	if report.Summary.ELFParseErrors != 0 || observed < 6 || compared < 24 || !apiAbsent {
		t.Fatal("oracle did not cover expected target", report.Summary, observed, absent, compared, apiAbsent)
	}
	candidate, err := report.RuntimeClosure("usr/sbin/smbd")
	if err != nil || !candidate.StaticDependenciesResolved || candidate.RuntimeQualified || candidate.ExecutionAuthorized {
		t.Fatal("attribute observation changed the graph's separate authority boundary", candidate, err)
	}
	t.Logf("actual pinned target: observed=%d absent=%d readelf-tag-comparisons=%d API-absence=true target-executed=false", observed, absent, compared)
}
