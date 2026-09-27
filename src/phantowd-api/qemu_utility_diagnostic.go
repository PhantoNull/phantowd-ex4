// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import "strings"

const maxQEMUUtilityDiagnosticBytes = 4096

// qemuUtilityDiagnostic retains bounded, single-line stderr from fixed
// disposable-fixture tools so a failed guest smoke identifies its command.
type qemuUtilityDiagnostic struct {
	data      []byte
	truncated bool
}

func (diagnostic *qemuUtilityDiagnostic) Write(data []byte) (int, error) {
	length := len(data)
	remaining := maxQEMUUtilityDiagnosticBytes - len(diagnostic.data)
	if remaining > 0 {
		if len(data) > remaining {
			data = data[:remaining]
			diagnostic.truncated = true
		}
		diagnostic.data = append(diagnostic.data, data...)
	} else if length > 0 {
		diagnostic.truncated = true
	}
	return length, nil
}

func (diagnostic qemuUtilityDiagnostic) String() string {
	text := strings.Join(strings.Fields(string(diagnostic.data)), " ")
	if diagnostic.truncated {
		text += " [truncated]"
	}
	return text
}
