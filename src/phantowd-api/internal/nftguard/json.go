// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package nftguard checks the kernel's nftables readback against a fixed policy.
package nftguard

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strconv"
)

var ErrState = errors.New("unexpected nftables state")

type Object = map[string]any

func ParseObjects(output []byte) ([]Object, error) {
	decoder := json.NewDecoder(bytes.NewReader(output))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	var document struct {
		Objects []Object `json:"nftables"`
	}
	if decoder.Decode(&document) != nil || decoder.Decode(new(any)) != io.EOF || len(document.Objects) == 0 {
		return nil, ErrState
	}
	first := document.Objects[0]
	meta, ok := first["metainfo"].(map[string]any)
	if !ok || len(first) != 1 || meta["json_schema_version"] != json.Number("1") {
		return nil, ErrState
	}
	return document.Objects[1:], nil
}

func RequireAbsent(objects []Object, family, name string) error {
	for _, object := range objects {
		table, ok := object["table"].(map[string]any)
		if !ok || len(object) != 1 {
			return ErrState
		}
		observedFamily, familyOK := table["family"].(string)
		observedName, nameOK := table["name"].(string)
		if !familyOK || !nameOK || observedFamily == family && observedName == name {
			return ErrState
		}
	}
	return nil
}

func MatchObject(wrapper Object, kind string, want Object) (uint64, error) {
	object, ok := wrapper[kind].(map[string]any)
	if !ok || len(wrapper) != 1 || len(object) != len(want)+1 {
		return 0, ErrState
	}
	number, ok := object["handle"].(json.Number)
	handle, err := strconv.ParseUint(string(number), 10, 64)
	if !ok || err != nil || handle == 0 {
		return 0, ErrState
	}
	for key, value := range want {
		if observed, exists := object[key]; !exists || !reflect.DeepEqual(observed, value) {
			return 0, ErrState
		}
	}
	return handle, nil
}

func Match(left, right any) Object {
	return Object{"match": Object{"op": "==", "left": left, "right": right}}
}

func Payload(protocol, field string) Object {
	return Object{"payload": Object{"protocol": protocol, "field": field}}
}
