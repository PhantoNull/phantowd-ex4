//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsipolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsipreview"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/nfsconfig"
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
	coherent := naspolicy.Config{Format: naspolicy.Format, SchemaVersion: 1, Revision: volumes.Revision,
		FileServices: fileservice.Config{Format: fileservice.ConfigFormat, SchemaVersion: 1, Revision: volumes.Revision,
			Shares: volumes, NFS: nfsconfig.Policy{Format: nfsconfig.Format, SchemaVersion: 1,
				Revision: volumes.Revision, VolumeRevision: volumes.Revision, Exports: []nfsconfig.Export{}}}, ISCSI: p}
	coherent.ISCSI.Revision = volumes.Revision
	preview, err := iscsipreview.Build(coherent)
	if err != nil || preview.Revision != "7" || preview.StorageValidated || preview.CredentialsValidated ||
		preview.RuntimeValidated || preview.ActivationAvailable || len(preview.Targets) != 1 || len(preview.Backings) != 1 ||
		preview.Backings[0].CapacityBytes != "1073741824" || preview.Targets[0].LUNs[0].Number != 0 ||
		preview.Targets[0].Initiators[0].Grants[0].Access != "ro" {
		return errors.New("synthetic desired iSCSI preview failed")
	}
	encoded, err := json.Marshal(preview)
	if err != nil || len(encoded) > iscsipreview.MaxOutputBytes || strings.Contains(string(encoded), "fixture-inbound") ||
		strings.Contains(string(encoded), "fixture-outbound") || strings.Contains(string(encoded), "secret_ref") {
		return errors.New("synthetic desired iSCSI preview disclosure or bounds failure")
	}
	coherent.ISCSI.Revision++
	if invalid, err := iscsipreview.Build(coherent); err != iscsipreview.ErrInvalid || invalid.Format != "" || invalid.Targets != nil || invalid.Backings != nil {
		return errors.New("synthetic desired iSCSI preview admitted stale policy")
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
