// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package naspolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsipolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/nfsconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

func testConfig() Config {
	return Config{Format: Format, SchemaVersion: SchemaVersion, Revision: 1,
		FileServices: fileservice.Config{Format: fileservice.ConfigFormat, SchemaVersion: 1, Revision: 1,
			Shares: shareconfig.Config{Format: shareconfig.Format, SchemaVersion: 1, Revision: 1,
				Volumes: []shareconfig.Volume{{ID: "bulk", FilesystemUUID: "11111111-2222-3333-4444-555555555555"}}, Users: []shareconfig.User{}, Shares: []shareconfig.Share{}},
			NFS: nfsconfig.Policy{Format: nfsconfig.Format, SchemaVersion: 1, Revision: 1, VolumeRevision: 1, Exports: []nfsconfig.Export{}}},
		ISCSI: iscsipolicy.Policy{Format: iscsipolicy.Format, SchemaVersion: 1, Revision: 1, VolumeRevision: 1,
			Backings: []iscsipolicy.Backing{{ID: "disk", VolumeID: "bulk", RelativePath: "luns/disk.img", CapacityBytes: 4096, BlockSize: 512, Allocation: "preallocated"}},
			Targets: []iscsipolicy.Target{{ID: "target", Name: "iqn.2001-04.com.example:target", State: "disabled",
				LUNs: []iscsipolicy.LUN{{ID: "lun", Number: 0, BackingID: "disk", Access: "ro"}},
				Initiators: []iscsipolicy.Initiator{{Name: "iqn.2001-04.com.example:peer",
					Authentication: iscsipolicy.Authentication{Mode: "chap", InitiatorUser: "peer", InitiatorSecretRef: "inbound"},
					Grants:         []iscsipolicy.Grant{{LUNID: "lun", Access: "ro"}}}}}}}}
}

func TestCoherentPolicyRoundTripAndIndependentCountersRefused(t *testing.T) {
	c := testConfig()
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(bytes.NewReader(data))
	if err != nil || !reflect.DeepEqual(got, c) {
		t.Fatal("roundtrip", err)
	}
	for _, mutate := range []func(*Config){
		func(c *Config) { c.Revision++ },
		func(c *Config) { c.FileServices.Revision++ },
		func(c *Config) { c.FileServices.Shares.Revision++ },
		func(c *Config) { c.FileServices.NFS.Revision++ },
		func(c *Config) { c.FileServices.NFS.VolumeRevision++ },
		func(c *Config) { c.ISCSI.Revision++ },
		func(c *Config) { c.ISCSI.VolumeRevision++ },
		func(c *Config) { c.ISCSI.Backings[0].VolumeID = "foreign" },
	} {
		bad := testConfig()
		mutate(&bad)
		if bad.Validate() != ErrInvalid {
			t.Fatal("mixed policy validated")
		}
		data, _ := json.Marshal(bad)
		if got, err := Decode(bytes.NewReader(data)); err != ErrInvalid || !reflect.DeepEqual(got, Config{}) {
			t.Fatal("mixed policy returned partial state", err)
		}
	}
}

type failedReader struct{}

func (failedReader) Read([]byte) (int, error) { return 0, errors.New("PRIVATE I/O DETAIL") }

func TestPolicyStrictJSONAndRedaction(t *testing.T) {
	data, _ := json.Marshal(testConfig())
	valid := string(data)
	for _, bad := range []string{
		`null`, `{}`, valid + `{}`, strings.Replace(valid, `"format":`, `"Format":`, 1),
		strings.Replace(valid, `"revision":1`, `"revision":1,"revision":1`, 1),
		strings.Replace(valid, `"number":0,`, "", 1),
		strings.Replace(valid, `"iscsi":{`, `"iscsi":null,"ignored":{`, 1),
		strings.Replace(valid, `"relative_path":"luns/disk.img"`, `"relative_path":"\ud800"`, 1),
		strings.Repeat(" ", MaxInputBytes+1),
	} {
		if got, err := Decode(strings.NewReader(bad)); err != ErrInvalid || !reflect.DeepEqual(got, Config{}) {
			t.Fatal("invalid JSON escaped zero/redacted contract", err)
		}
	}
	if got, err := Decode(failedReader{}); err != ErrInvalid || !reflect.DeepEqual(got, Config{}) {
		t.Fatal(err)
	}
	if got, err := Decode(nil); err != ErrInvalid || !reflect.DeepEqual(got, Config{}) {
		t.Fatal(err)
	}
}
