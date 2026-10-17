//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
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
	if err := exerciseQEMUNASPolicyEdits(coherent); err != nil {
		return err
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

// Pure all-protocol edit checks in the existing guest self-test. The 1GiB
// backing is a desired reference only; no backing, secret or device is opened.
func exerciseQEMUNASPolicyEdits(base naspolicy.Config) error {
	fail := func() error { return errors.New("synthetic all-protocol policy edit failed") }
	base.FileServices.Shares.Users = []shareconfig.User{{ID: "reader", Name: "reader"}}
	base.FileServices.Shares.Shares = []shareconfig.Share{{ID: "books", Name: "Books", VolumeID: "fixture-volume", RelativePath: "books", Grants: []shareconfig.Grant{{UserID: "reader", Access: "ro"}}}}
	base.FileServices.NFS.Exports = []nfsconfig.Export{{ID: "66666666-7777-4888-8999-aaaaaaaaaaaa", VolumeID: "fixture-volume", RelativePath: "books",
		Clients: []nfsconfig.Client{{Network: "198.51.100.7/32", Access: "ro", Squash: "all", AnonymousUID: 65534, AnonymousGID: 65534, Security: "sys"}}}}
	original, err := json.Marshal(base)
	if err != nil || base.Validate() != nil {
		return fail()
	}
	fileBytes, err := json.Marshal(base.FileServices)
	if err != nil {
		return fail()
	}
	files, err := fileservice.DecodeConfig(bytes.NewReader(fileBytes))
	if err != nil {
		return fail()
	}
	files.Revision = 8
	files.Shares.Revision = 8
	files.NFS.Revision, files.NFS.VolumeRevision = 8, 8
	files.Shares.Shares[0].Grants[0].Access = "rw"
	first, err := naspolicy.ReplaceFileServices(base, files)
	wantISCSI := base.ISCSI
	wantISCSI.Revision, wantISCSI.VolumeRevision = 8, 8
	if err != nil || first.Validate() != nil || !reflect.DeepEqual(first.ISCSI, wantISCSI) || first.Revision != 8 {
		return fail()
	}
	iscsiBytes, err := json.Marshal(first.ISCSI)
	if err != nil {
		return fail()
	}
	next, err := iscsipolicy.Decode(bytes.NewReader(iscsiBytes), first.FileServices.Shares)
	if err != nil {
		return fail()
	}
	next.Revision, next.VolumeRevision = 9, 9
	next.Targets[0].LUNs[0].Access = "rw"
	next.Targets[0].Initiators[0].Grants[0].Access = "rw"
	second, err := naspolicy.ReplaceISCSI(first, next)
	wantFiles := first.FileServices
	wantFiles.Revision, wantFiles.Shares.Revision = 9, 9
	wantFiles.NFS.Revision, wantFiles.NFS.VolumeRevision = 9, 9
	if err != nil || second.Validate() != nil || second.Revision != 9 || !reflect.DeepEqual(second.FileServices, wantFiles) {
		return fail()
	}
	first.ISCSI.Targets[0].Initiators[0].Authentication.InitiatorSecretRef = "other-ref"
	second.FileServices.NFS.Exports[0].Clients[0].Access = "rw"
	after, err := json.Marshal(base)
	if err != nil || !bytes.Equal(original, after) || next.Targets[0].Initiators[0].Authentication.InitiatorSecretRef != "fixture-inbound" || files.NFS.Exports[0].Clients[0].Access != "ro" {
		return fail()
	}
	if got, err := naspolicy.ReplaceISCSI(base, base.ISCSI); err != naspolicy.ErrInvalid || !reflect.DeepEqual(got, naspolicy.Config{}) {
		return fail()
	}
	files.Shares.Volumes[0].FilesystemUUID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	if got, err := naspolicy.ReplaceFileServices(base, files); err != naspolicy.ErrInvalid || !reflect.DeepEqual(got, naspolicy.Config{}) {
		return fail()
	}
	files.Shares.Volumes, files.Shares.Shares, files.NFS.Exports = []shareconfig.Volume{}, []shareconfig.Share{}, []nfsconfig.Export{}
	if got, err := naspolicy.ReplaceFileServices(base, files); files.Validate() != nil || err != naspolicy.ErrInvalid || !reflect.DeepEqual(got, naspolicy.Config{}) {
		return fail()
	}
	base.Revision = ^uint64(0)
	base.FileServices.Revision, base.FileServices.Shares.Revision = base.Revision, base.Revision
	base.FileServices.NFS.Revision, base.FileServices.NFS.VolumeRevision = base.Revision, base.Revision
	base.ISCSI.Revision, base.ISCSI.VolumeRevision = base.Revision, base.Revision
	if got, err := naspolicy.ReplaceISCSI(base, next); base.Validate() != nil || err != naspolicy.ErrInvalid || !reflect.DeepEqual(got, naspolicy.Config{}) {
		return fail()
	}
	fmt.Println("PHANTOWD_NAS_POLICY_EDIT_READY cases=7 coherent_revision=true detached=true cross_protocol_preserved=true publication=false scope=synthetic-policy-only")
	return nil
}
