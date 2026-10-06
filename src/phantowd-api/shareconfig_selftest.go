//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"errors"
	"strings"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

func exerciseQEMUShareConfig() error {
	const fixture = `{"format":"phantowd-share-config","schema_version":1,"revision":1,
"volumes":[{"id":"test-volume","filesystem_uuid":"11111111-2222-3333-4444-555555555555"}],
"users":[{"id":"test-reader","name":"reader"}],
"shares":[{"id":"test-share","name":"Books","volume_id":"test-volume","relative_path":"books",
"grants":[{"user_id":"test-reader","access":"ro"}]}]}`
	config, err := shareconfig.Decode(strings.NewReader(fixture))
	if err != nil || config.Shares[0].Grants[0].Access != "ro" {
		return errors.New("share policy did not preserve a valid read-only grant")
	}
	for _, invalid := range []string{
		strings.Replace(fixture, `"volume_id":"test-volume"`, `"volume_id":"absent"`, 1),
		strings.Replace(fixture, `"relative_path":"books"`, `"relative_path":"../outside"`, 1),
		strings.Replace(fixture, `"access":"ro"`, `"access":"rw","access":"ro"`, 1),
	} {
		if _, err := shareconfig.Decode(strings.NewReader(invalid)); err == nil {
			return errors.New("share policy accepted unsafe fixture")
		}
	}
	return nil
}
