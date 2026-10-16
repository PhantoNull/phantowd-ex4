// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package smartreport

import (
	"encoding/json"
	"strconv"
	"strings"
)

// TemperatureObservation is an offline tool-reported value, not a qualified
// thermal source. It retains no source identity, timestamp or report bytes.
// Missing evidence is distinct from a reported zero. Neither the temperature
// nor a passing health status establishes safe operating conditions.
type TemperatureObservation struct {
	health   Observation
	celsius  int16
	reported bool
}

func (o TemperatureObservation) Health() Observation { return o.health }
func (o TemperatureObservation) ReportedCelsius() (int16, bool) {
	return o.celsius, o.reported
}
func (TemperatureObservation) MarshalJSON() ([]byte, error) { return nil, ErrPrivate }
func (*TemperatureObservation) UnmarshalJSON([]byte) error  { return ErrPrivate }

// ParseATATemperature separately projects optional temperature.current from
// release smartctl 7.4/7.5 JSON 1.0 ATA reports. Parse's info+health contract is
// unchanged. This function authorizes no query, collector or thermal control.
// The admitted -128..127 interval covers these producers' signed ATA statistics
// and SCT fields; the attribute helper emits only 1..127. This is NOT a disk
// operating range or sensor calibration.
// Global JSON does not identify which ATA temperature source supplied the value.
func ParseATATemperature(data []byte, observedExit int) (TemperatureObservation, error) {
	root, err := readReport(data, observedExit)
	if err != nil {
		return TemperatureObservation{}, err
	}
	health, err := parseReport(root, observedExit)
	if err != nil {
		return TemperatureObservation{}, err
	}
	o := TemperatureObservation{health: health}
	if health.State() == UnsupportedProtocol {
		return o, nil // Never interpret another protocol's temperature as ATA.
	}
	for key := range root {
		if key != "temperature" && strings.EqualFold(key, "temperature") {
			return TemperatureObservation{}, ErrInvalid
		}
	}
	value, exists := root["temperature"]
	if !exists {
		return o, nil
	}
	fields, ok := value.(map[string]any)
	if !ok {
		return TemperatureObservation{}, ErrInvalid
	}
	for key := range fields {
		if key != "current" && strings.EqualFold(key, "current") {
			return TemperatureObservation{}, ErrInvalid
		}
	}
	value, exists = fields["current"]
	if !exists {
		return o, nil
	}
	number, ok := value.(json.Number)
	if !ok {
		return TemperatureObservation{}, ErrInvalid
	}
	// ParseInt rejects fractions/exponents. -0 is not emitted by this profile.
	n, err := strconv.ParseInt(string(number), 10, 16)
	if err != nil || n < -128 || n > 127 || number == "-0" {
		return TemperatureObservation{}, ErrInvalid
	}
	// A valid optional value does not make unavailable health/capability evidence
	// usable. In particular, do not turn disabled SMART into a current sample.
	if health.State() == Complete || health.State() == Partial {
		o.celsius, o.reported = int16(n), true
	}
	return o, nil
}
