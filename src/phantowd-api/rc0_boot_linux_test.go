// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"strings"
	"testing"
)

func TestRC0BootPlanRequiresExplicitBoundStateAndIdentity(t *testing.T) {
	digest := strings.Repeat("a", 64)
	valid := `{"format":"phantowd-rc0-boot-v1","installation_id":"c71c2ba76bd04d29816335c13c31a380",` +
		`"listen_address":"127.0.0.1:8443","origin":"https://127.0.0.1:8443","state_mount_id":6000000001,` +
		`"state_root_inode":12,"policy_sha256":"` + digest + `","tls_leaf_sha256":"` + digest + `"}`
	plan, err := decodeRC0BootPlan([]byte(valid))
	if err != nil || plan.StateMountID != 6000000001 || plan.StateRootInode != 12 || plan.TLSLeafSHA256 != digest {
		t.Fatalf("valid boot handoff was refused: %v", err)
	}
	for name, input := range map[string]string{
		"plaintext":  strings.Replace(valid, "https://", "http://", 1),
		"wrong port": strings.Replace(valid, "https://127.0.0.1:8443", "https://127.0.0.1:8444", 1),
		"duplicate":  `{"origin":"https://127.0.0.1:8443",` + valid[1:],
		"unknown":    `{"device_path":"/untrusted",` + valid[1:],
		"no mount":   strings.Replace(valid, `"state_mount_id":6000000001,`, "", 1),
		"no inode":   strings.Replace(valid, `"state_root_inode":12,`, "", 1),
		"bad hash":   strings.Replace(valid, digest, strings.Repeat("A", 64), 1),
		"trailing":   valid + "{}",
		"oversize":   valid + strings.Repeat(" ", rc0BootMaxBytes),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeRC0BootPlan([]byte(input)); err == nil {
				t.Fatal("unqualified boot handoff was accepted")
			}
		})
	}
}
