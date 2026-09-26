// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package fileservice

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"testing"
)

func configFixture(revision uint64) Config {
	shares, nfs := fixture()
	shares.Revision, nfs.Revision, nfs.VolumeRevision = revision, revision, revision
	return Config{Format: ConfigFormat, SchemaVersion: 1, Revision: revision, Shares: shares, NFS: nfs}
}

func TestCombinedConfigRoundTrip(t *testing.T) {
	want := configFixture(7)
	data, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeConfig(bytes.NewReader(data))
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal(got, err)
	}
	preview, err := Build(got.Shares, got.NFS)
	if err != nil || preview.Persisted || preview.Applied || preview.RuntimeValidated || preview.ActivationAvailable {
		t.Fatal("stored policy became activation authority", err)
	}
}

func TestCombinedConfigRefusesSplitRevisions(t *testing.T) {
	for _, mutate := range []func(*Config){
		func(c *Config) { c.Revision = 0 },
		func(c *Config) { c.SchemaVersion = 2 },
		func(c *Config) { c.Shares.Revision++ },
		func(c *Config) { c.NFS.Revision++ },
		func(c *Config) { c.NFS.VolumeRevision++ },
		func(c *Config) { c.NFS.Exports[0].VolumeID = "missing" },
		func(c *Config) { c.Shares.Shares[0].RelativePath = "books%U" },
		func(c *Config) { c.Shares.Users = nil },
	} {
		c := configFixture(7)
		mutate(&c)
		data, _ := json.Marshal(c)
		if c.Validate() == nil {
			t.Fatal("invalid constructed policy accepted")
		}
		if _, err := DecodeConfig(bytes.NewReader(data)); !errors.Is(err, ErrConfig) {
			t.Fatal(err)
		}
	}
}

func TestCombinedConfigStrictEnvelope(t *testing.T) {
	data, _ := json.Marshal(configFixture(7))
	for name, input := range map[string][]byte{
		"empty": nil, "null": []byte("null"), "array": []byte("[]"),
		"missing":           bytes.Replace(data, []byte(`"revision":7,`), nil, 1),
		"duplicate":         bytes.Replace(data, []byte(`"revision":7`), []byte(`"revision":7,"revision":7`), 1),
		"escaped duplicate": bytes.Replace(data, []byte(`"revision":7`), []byte(`"revision":7,"revisio\u006e":7`), 1),
		"null nested":       bytes.Replace(data, []byte(`"nfs":{`), []byte(`"nfs":null,"unused":{`), 1),
		"case alias":        bytes.Replace(data, []byte(`"revision"`), []byte(`"Revision"`), 1),
		"unknown":           bytes.Replace(data, []byte(`"revision"`), []byte(`"unexpected"`), 1),
		"negative":          bytes.Replace(data, []byte(`"revision":7`), []byte(`"revision":-1`), 1),
		"overflow":          bytes.Replace(data, []byte(`"revision":7`), []byte(`"revision":18446744073709551616`), 1),
		"float":             bytes.Replace(data, []byte(`"revision":7`), []byte(`"revision":7.0`), 1),
		"nested duplicate":  bytes.Replace(data, []byte(`"volume_revision":7`), []byte(`"volume_revision":7,"volume_revision":7`), 1),
		"malformed unicode": bytes.Replace(data, []byte(`"relative_path":"books"`), []byte(`"relative_path":"\ud800"`), 1),
		"trailing":          append(append([]byte{}, data...), []byte("{}")...),
		"oversized":         bytes.Repeat([]byte(" "), MaxConfigBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeConfig(bytes.NewReader(input)); !errors.Is(err, ErrConfig) {
				t.Fatal("accepted", err)
			}
		})
	}
	if _, err := DecodeConfig(errorReader{}); !errors.Is(err, ErrConfig) {
		t.Fatal(err)
	}
	proposalShares, proposalNFS := fixture()
	if _, err := DecodeConfig(bytes.NewReader(encode(proposalShares, proposalNFS))); !errors.Is(err, ErrConfig) {
		t.Fatal("implicit proposal migration")
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func FuzzCombinedConfig(f *testing.F) {
	data, _ := json.Marshal(configFixture(1))
	f.Add(data)
	f.Add([]byte(`{"revision":1}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := DecodeConfig(bytes.NewReader(data))
		if err != nil {
			return
		}
		if c.Validate() != nil || c.Shares.Revision != c.NFS.VolumeRevision || c.Revision != c.NFS.Revision {
			t.Fatal("incoherent accepted policy")
		}
		encoded, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		again, err := DecodeConfig(bytes.NewReader(encoded))
		if err != nil || !reflect.DeepEqual(c, again) {
			t.Fatal("unstable round trip", err)
		}
	})
}
