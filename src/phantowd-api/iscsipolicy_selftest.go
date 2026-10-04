//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"errors"
	"strings"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsipolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

// Pure desired-policy fixture: no file, socket, target, credential or disk I/O.
func exerciseQEMUISCSIPolicy() error {
	volumes := shareconfig.Config{Format: shareconfig.Format, SchemaVersion: 1, Revision: 7,
		Volumes: []shareconfig.Volume{{ID: "fixture-volume", FilesystemUUID: "12345678-1234-1234-1234-123456789abc"}},
		Users:   []shareconfig.User{}, Shares: []shareconfig.Share{}}
	const fixture = `{"format":"phantowd-iscsi-policy","schema_version":1,"revision":2,"volume_revision":7,
"backings":[{"id":"fixture-backing","volume_id":"fixture-volume","relative_path":"luns/fixture.img","capacity_bytes":1073741824,"block_size":512,"allocation":"preallocated"}],
"targets":[{"id":"fixture-target","name":"iqn.2001-04.com.example:fixture-target","state":"disabled",
"luns":[{"id":"fixture-lun","number":0,"backing_id":"fixture-backing","access":"ro"}],
"initiators":[{"name":"iqn.2001-04.com.example:fixture-initiator",
"authentication":{"mode":"mutual-chap","initiator_user":"fixture-peer","initiator_secret_ref":"fixture-inbound","target_user":"fixture-target","target_secret_ref":"fixture-outbound"},
"grants":[{"lun_id":"fixture-lun","access":"ro"}]}]}]}`
	p, err := iscsipolicy.Decode(strings.NewReader(fixture), volumes)
	if err != nil || len(p.Targets) != 1 || p.Targets[0].LUNs[0].Number != 0 || p.Validate(volumes) != nil {
		return errors.New("synthetic iSCSI policy positive fixture failed")
	}
	for _, input := range []string{
		strings.Replace(fixture, `"number":0,`, "", 1),
		strings.Replace(fixture, `"number":0`, `"number":65536`, 1),
		strings.Replace(fixture, `"number":0`, `"Number":0`, 1),
		strings.Replace(fixture, `"volume_revision":7`, `"volume_revision":8`, 1),
		strings.Replace(fixture, `"volume_id":"fixture-volume"`, `"volume_id":"missing"`, 1),
		strings.Replace(fixture, `"target_secret_ref":"fixture-outbound"`, `"target_secret_ref":"fixture-inbound"`, 1),
		strings.Replace(fixture, `"lun_id":"fixture-lun"`, `"lun_id":"foreign-lun"`, 1),
		strings.Replace(fixture, `"lun_id":"fixture-lun","access":"ro"`, `"lun_id":"fixture-lun","access":"rw"`, 1),
		strings.Replace(fixture, `"capacity_bytes":1073741824`, `"capacity_bytes":9223372036854775808`, 1),
		strings.Replace(fixture, `"relative_path":"luns/fixture.img"`, `"relative_path":"../fixture.img"`, 1),
		strings.Replace(fixture, `"mode":"mutual-chap"`, `"mode":"none"`, 1),
	} {
		p, err := iscsipolicy.Decode(strings.NewReader(input), volumes)
		if err != iscsipolicy.ErrInvalid || p.Format != "" || p.Targets != nil || p.Backings != nil {
			return errors.New("synthetic iSCSI policy refusal fixture failed")
		}
	}
	return nil
}
