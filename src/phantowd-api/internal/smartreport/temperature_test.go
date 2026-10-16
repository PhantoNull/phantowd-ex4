// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package smartreport

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func temperatureFixture(exit int, passed bool, field string) []byte {
	return []byte(strings.TrimSuffix(fixture(exit, passed), "}") + field + "}")
}

func TestATATemperatureProjection(t *testing.T) {
	for _, minor := range []int{4, 5} {
		for _, tc := range []struct {
			field    string
			value    int16
			reported bool
		}{
			{"", 0, false},
			{`,"temperature":{}`, 0, false},
			{`,"temperature":{"lifetime_max":45}`, 0, false},
			{`,"temperature":{"current":0}`, 0, true},
			{`,"temperature":{"current":37}`, 37, true},
			{`,"temperature":{"current":-128}`, -128, true},
			{`,"temperature":{"current":-1}`, -1, true},
			{`,"temperature":{"current":127}`, 127, true},
		} {
			for exit := 0; exit <= 255; exit++ {
				data := temperatureFixture(exit, exit&8 == 0, tc.field)
				data = []byte(strings.Replace(string(data), `"version":[7,4]`, fmt.Sprintf(`"version":[7,%d]`, minor), 1))
				o, err := ParseATATemperature(data, exit)
				health, baseErr := Parse(data, exit)
				value, reported := o.ReportedCelsius()
				if err != nil || baseErr != nil || o.Health() != health || value != tc.value || reported != tc.reported {
					t.Fatalf("projection mismatch: release=%d exit=%d error=%v", minor, exit, err)
				}
			}
		}
	}
}

func TestATATemperatureRefusalsDoNotChangeHealthParser(t *testing.T) {
	for _, field := range []string{
		`null`, `true`, `[]`, `"PRIVATE"`,
		`{"current":null}`, `{"current":true}`, `{"current":"37"}`,
		`{"current":[]}`, `{"current":{}}`, `{"current":37.0}`,
		`{"current":3.7e1}`, `{"current":-0}`, `{"current":-129}`,
		`{"current":128}`, `{"current":255}`, `{"current":256}`, `{"current":999999999999999999999999}`,
		`{"Current":37}`,
	} {
		data := temperatureFixture(0, true, `,"temperature":`+field)
		o, err := ParseATATemperature(data, 0)
		if o != (TemperatureObservation{}) || !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid optional value accepted", field)
		}
		if _, err := Parse(data, 0); err != nil {
			t.Fatal("original health parser changed", err)
		}
	}
	for _, field := range []string{
		`,"Temperature":{"current":37}`,
		`,"temperature":{"current":37,"Current":37}`,
		`,"temperature":{"current":37,"current":37}`,
		`,"temperature":{},"temperature":{}`,
	} {
		o, err := ParseATATemperature(temperatureFixture(0, true, field), 0)
		if o != (TemperatureObservation{}) || !errors.Is(err, ErrInvalid) {
			t.Fatal("alias/duplicate accepted")
		}
	}
	data := temperatureFixture(0, true, `,"temperature":{"current":37}`)
	for _, exit := range []int{-1, 1, 256} {
		if o, err := ParseATATemperature(data, exit); o != (TemperatureObservation{}) || err != ErrInvalid {
			t.Fatal("invalid process result accepted")
		}
	}
}

func TestATATemperatureUnusableAndOtherProtocol(t *testing.T) {
	for _, tc := range []struct {
		body  string
		exit  int
		state State
	}{
		{`"device":{"protocol":"ATA"},"smart_support":{"available":true,"enabled":false}`, 0, Disabled},
		{`"device":{"protocol":"ATA"},"smart_support":{"available":false}`, 4, UnsupportedSMART},
		{`"device":{"protocol":"ATA"}`, 2, Unavailable},
		{`"device":{"protocol":"NVMe"}`, 0, UnsupportedProtocol},
	} {
		data := []byte(fmt.Sprintf(`{"json_format_version":[1,0],"smartctl":{"version":[7,5],"pre_release":false,"exit_status":%d},%s,"temperature":{"current":37}}`, tc.exit, tc.body))
		o, err := ParseATATemperature(data, tc.exit)
		if value, reported := o.ReportedCelsius(); err != nil || value != 0 || reported || o.Health().State() != tc.state {
			t.Fatal("unusable report gained ATA sample", err)
		}
	}
	// Other protocols' optional fields are not this profile's business.
	data := strings.Replace(string(temperatureFixture(0, true, `,"temperature":null`)), `"protocol":"ATA"`, `"protocol":"NVMe"`, 1)
	if o, err := ParseATATemperature([]byte(data), 0); err != nil || o.Health().State() != UnsupportedProtocol {
		t.Fatal("non-ATA optional field interpreted")
	}
}

func TestATATemperaturePrivacy(t *testing.T) {
	data := temperatureFixture(0, true, `,"temperature":{"current":37,"private":"PRIVATE-TEMP"}`)
	o, err := ParseATATemperature(data, 0)
	if err != nil {
		t.Fatal(err)
	}
	for i := range data {
		data[i] = 0
	}
	if value, reported := o.ReportedCelsius(); value != 37 || !reported || strings.Contains(fmt.Sprintf("%+v", o), "PRIVATE") {
		t.Fatal("raw report retained")
	}
	if _, err := json.Marshal(o); !errors.Is(err, ErrPrivate) {
		t.Fatal("internal projection serialized")
	}
	before := o
	if err := json.Unmarshal([]byte(`{"celsius":37}`), &o); !errors.Is(err, ErrPrivate) || o != before {
		t.Fatal("JSON replaced projection")
	}
	if typ := reflect.TypeOf(o); typ.NumField() != 3 || typ.Field(0).Type != reflect.TypeOf(Observation{}) || typ.Field(1).Type.Kind() != reflect.Int16 || typ.Field(2).Type.Kind() != reflect.Bool {
		t.Fatal("raw or unbounded field added")
	}
	if value, reported := (TemperatureObservation{}).ReportedCelsius(); value != 0 || reported {
		t.Fatal("zero projection claims sample")
	}
}

func FuzzATATemperature(f *testing.F) {
	f.Add(temperatureFixture(0, true, `,"temperature":{"current":37}`), 0)
	f.Add(temperatureFixture(12, false, `,"temperature":{"current":0}`), 12)
	f.Add(temperatureFixture(0, true, `,"temperature":null`), 0)
	f.Fuzz(func(t *testing.T, data []byte, exit int) {
		o, err := ParseATATemperature(data, exit)
		if err != nil {
			if o != (TemperatureObservation{}) || (err != ErrInvalid && err != ErrUnsupportedFormat) {
				t.Fatal("non-atomic or unredacted refusal")
			}
			return
		}
		health, baseErr := Parse(data, exit)
		value, reported := o.ReportedCelsius()
		if baseErr != nil || o.Health() != health || (reported && (value < -128 || value > 127 || (health.State() != Complete && health.State() != Partial))) || (!reported && value != 0) {
			t.Fatal("incoherent projection")
		}
		if _, err := json.Marshal(o); !errors.Is(err, ErrPrivate) {
			t.Fatal("internal projection serialized")
		}
	})
}
