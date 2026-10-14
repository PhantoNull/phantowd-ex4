// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package fileservice

import (
	"bytes"
	"errors"
	"math"
	"reflect"
	"testing"
)

func TestBackupRoundTripAndRevisionRebase(t *testing.T) {
	original := configFixture(73)
	data, err := EncodeBackup(original)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := append([]byte{}, data...)
	for _, expected := range []uint64{0, 2, 101, math.MaxUint64 - 1} {
		got, err := RestoreCandidate(data, expected)
		want := configFixture(expected + 1)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatal(expected, got, err)
		}
		preview, err := Build(got.Shares, got.NFS)
		if err != nil || preview.Persisted || preview.Applied || preview.RuntimeValidated || preview.ActivationAvailable {
			t.Fatal("activation authority", err)
		}
	}
	if !bytes.Equal(data, snapshot) || !reflect.DeepEqual(original, configFixture(73)) {
		t.Fatal("input mutated")
	}
	if got, err := RestoreCandidate(data, math.MaxUint64); !errors.Is(err, ErrBackup) || !reflect.DeepEqual(got, Config{}) {
		t.Fatal("overflow accepted")
	}
	if data, err := EncodeBackup(Config{}); !errors.Is(err, ErrBackup) || data != nil {
		t.Fatal("invalid source exported")
	}
}

func TestBackupStrictOriginalBytes(t *testing.T) {
	data, err := EncodeBackup(configFixture(7))
	if err != nil {
		t.Fatal(err)
	}
	for name, input := range map[string][]byte{
		"empty": nil, "null": []byte("null"), "array": []byte("[]"),
		"wrong format":       bytes.Replace(data, []byte(BackupFormat), []byte(ConfigFormat), 1),
		"wrong version":      bytes.Replace(data, []byte(`"schema_version":1`), []byte(`"schema_version":2`), 1),
		"missing":            bytes.Replace(data, []byte(`"schema_version":1,`), nil, 1),
		"unknown secret":     bytes.Replace(data, []byte(`"schema_version":1`), []byte(`"schema_version":1,"password":"private-secret"`), 1),
		"case":               bytes.Replace(data, []byte(`"format"`), []byte(`"Format"`), 1),
		"duplicate":          bytes.Replace(data, []byte(`"schema_version":1`), []byte(`"schema_version":1,"schema_version":1`), 1),
		"escaped duplicate":  bytes.Replace(data, []byte(`"schema_version":1`), []byte(`"schema_version":1,"schema_versio\u006e":1`), 1),
		"nested duplicate":   bytes.Replace(data, []byte(`"revision":7`), []byte(`"revision":7,"revision":7`), 1),
		"unknown nested":     bytes.Replace(data, []byte(`"volume_revision":7`), []byte(`"volume_revision":7,"password":"private-secret"`), 1),
		"split":              bytes.Replace(data, []byte(`"revision":7`), []byte(`"revision":8`), 1),
		"null configuration": []byte(`{"format":"phantowd-file-service-backup","schema_version":1,"configuration":null}`),
		"bad Unicode":        bytes.Replace(data, []byte(`"relative_path":"books"`), []byte(`"relative_path":"\ud800"`), 1),
		"bad UTF8":           append(append([]byte{}, data...), 0xff),
		"trailing":           append(append([]byte{}, data...), []byte("{}")...),
		"oversize":           bytes.Repeat([]byte(" "), MaxBackupBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			got, err := RestoreCandidate(input, 9)
			if err != ErrBackup || !reflect.DeepEqual(got, Config{}) {
				t.Fatal("invalid backup returned partial data", err)
			}
		})
	}
}
