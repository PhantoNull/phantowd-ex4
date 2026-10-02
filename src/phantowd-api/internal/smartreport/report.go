// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package smartreport interprets bounded, offline smartctl JSON observations.
// It does not run commands, open devices or establish identity, freshness,
// transport compatibility, collection policy or data integrity.
package smartreport

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	MaxBytes  = 64 * 1024
	maxDepth  = 12
	maxTokens = 8192
	maxString = 4096
	maxKey    = 128
)

var (
	ErrInvalid           = errors.New("invalid SMART report")
	ErrUnsupportedFormat = errors.New("unsupported SMART report format")
	ErrPrivate           = errors.New("SMART observation is internal")
)

// State describes the report, not the disk's overall health.
type State uint8

const (
	NotObserved State = iota
	Complete
	Partial
	Unavailable
	UnsupportedProtocol
	UnsupportedSMART
	Disabled
)

type Assessment uint8

const (
	NoAssessment Assessment = iota
	ReportedPass
	ReportedFail
)

// Flags preserves the ATA exit-bit meanings independently of assessment.
// False means the tool did not set that bit, not that a check ran successfully.
type Flags struct {
	CommandError            bool
	DeviceOrPowerError      bool
	SMARTCommandError       bool
	FailingStatus           bool
	CurrentPrefailThreshold bool
	HistoricalThreshold     bool
	ErrorLogRecords         bool
	SelfTestLogRecords      bool
}

// Observation retains only fixed states and bits, never report bytes, identities,
// tool messages or timestamps. It is not an HTTP DTO or a device authorization.
type Observation struct {
	state      State
	assessment Assessment
	exit       uint8
}

func (o Observation) State() State           { return o.state }
func (o Observation) Assessment() Assessment { return o.assessment }
func (o Observation) Flags() Flags {
	return Flags{
		CommandError:            o.exit&1 != 0,
		DeviceOrPowerError:      o.exit&2 != 0,
		SMARTCommandError:       o.exit&4 != 0,
		FailingStatus:           o.exit&8 != 0,
		CurrentPrefailThreshold: o.exit&16 != 0,
		HistoricalThreshold:     o.exit&32 != 0,
		ErrorLogRecords:         o.exit&64 != 0,
		SelfTestLogRecords:      o.exit&128 != 0,
	}
}
func (Observation) MarshalJSON() ([]byte, error) { return nil, ErrPrivate }
func (*Observation) UnmarshalJSON([]byte) error  { return ErrPrivate }

// Parse accepts the deliberately narrow smartctl 7.4 release / JSON 1.0 ATA
// info+health report profile. observedExit must come separately from the process
// result, not from this JSON. Neither matching values nor version strings prove
// the report's provenance. Unknown fields are discarded after bounded syntax
// validation. An incomplete collection can still contain a reported failure.
func Parse(data []byte, observedExit int) (Observation, error) {
	if observedExit < 0 || observedExit > 255 || len(data) == 0 || len(data) > MaxBytes || !utf8.Valid(data) {
		return Observation{}, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	remaining := maxTokens
	v, err := readValue(d, 0, &remaining)
	if err != nil {
		return Observation{}, ErrInvalid
	}
	if _, err = d.Token(); !errors.Is(err, io.EOF) {
		return Observation{}, ErrInvalid
	}
	root, ok := v.(map[string]any)
	if !ok {
		return Observation{}, ErrInvalid
	}
	format, err := pair(root["json_format_version"])
	if err != nil {
		return Observation{}, ErrInvalid
	}
	tool, ok := root["smartctl"].(map[string]any)
	if !ok {
		return Observation{}, ErrInvalid
	}
	version, err := pair(tool["version"])
	if err != nil {
		return Observation{}, ErrInvalid
	}
	prerelease, ok := tool["pre_release"].(bool)
	if !ok {
		return Observation{}, ErrInvalid
	}
	exit, err := integer(tool["exit_status"])
	if err != nil || exit != observedExit {
		return Observation{}, ErrInvalid
	}
	if format != [2]int{1, 0} || version != [2]int{7, 4} || prerelease {
		return Observation{}, ErrUnsupportedFormat
	}

	protocol := ""
	if value, exists := root["device"]; exists {
		device, ok := value.(map[string]any)
		if !ok {
			return Observation{}, ErrInvalid
		}
		protocol, ok = device["protocol"].(string)
		if !ok || protocol == "" {
			return Observation{}, ErrInvalid
		}
	}
	available, enabled, supportSeen := false, false, false
	if value, exists := root["smart_support"]; exists {
		support, ok := value.(map[string]any)
		if !ok {
			return Observation{}, ErrInvalid
		}
		available, ok = support["available"].(bool)
		if !ok {
			return Observation{}, ErrInvalid
		}
		supportSeen = true
		if value, exists := support["enabled"]; exists {
			enabled, ok = value.(bool)
			if !ok || (!available && enabled) {
				return Observation{}, ErrInvalid
			}
		} else if available {
			return Observation{}, ErrInvalid
		}
	}
	passed, statusSeen := false, false
	if value, exists := root["smart_status"]; exists {
		status, ok := value.(map[string]any)
		if !ok {
			return Observation{}, ErrInvalid
		}
		passed, ok = status["passed"].(bool)
		if !ok {
			return Observation{}, ErrInvalid
		}
		statusSeen = true
	}
	// Exit meanings differ across protocols: do not project ATA flags onto others.
	if protocol != "" && protocol != "ATA" {
		return Observation{state: UnsupportedProtocol}, nil
	}
	o := Observation{state: Unavailable, exit: uint8(exit)}
	if protocol == "" || !supportSeen {
		if exit&7 == 0 || statusSeen || exit&8 != 0 {
			return Observation{}, ErrInvalid
		}
		return o, nil
	}
	if !available || !enabled {
		if statusSeen || exit&8 != 0 {
			return Observation{}, ErrInvalid
		}
		if !available {
			o.state = UnsupportedSMART
		} else {
			o.state = Disabled
		}
		return o, nil
	}
	if !statusSeen {
		if exit&7 == 0 || exit&8 != 0 {
			return Observation{}, ErrInvalid
		}
		return o, nil
	}
	if (!passed) != (exit&8 != 0) {
		return Observation{}, ErrInvalid
	}
	o.state = Complete
	if exit&7 != 0 {
		o.state = Partial
	}
	o.assessment = ReportedPass
	if !passed {
		o.assessment = ReportedFail
	}
	return o, nil
}

func integer(v any) (int, error) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, ErrInvalid
	}
	s := string(n)
	if s == "" {
		return 0, ErrInvalid
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, ErrInvalid
		}
	}
	x, err := strconv.Atoi(s)
	if err != nil || x > 255 {
		return 0, ErrInvalid
	}
	return x, nil
}

func pair(v any) ([2]int, error) {
	a, ok := v.([]any)
	if !ok || len(a) != 2 {
		return [2]int{}, ErrInvalid
	}
	x, err := integer(a[0])
	if err != nil {
		return [2]int{}, err
	}
	y, err := integer(a[1])
	if err != nil {
		return [2]int{}, err
	}
	return [2]int{x, y}, nil
}

// Token decoding bounds the entire tree, including ignored fields. Exact maps
// avoid encoding/json's case-insensitive struct-field matching. Duplicate/case
// aliases and replacement characters (including repaired surrogate escapes)
// are refused by this narrow tool-report profile, not silently normalized.
func readValue(d *json.Decoder, depth int, remaining *int) (any, error) {
	if depth > maxDepth || *remaining <= 0 {
		return nil, ErrInvalid
	}
	*remaining--
	t, err := d.Token()
	if err != nil {
		return nil, ErrInvalid
	}
	if s, ok := t.(string); ok {
		if !validString(s, maxString) {
			return nil, ErrInvalid
		}
		return s, nil
	}
	delim, compound := t.(json.Delim)
	if !compound {
		return t, nil
	}
	switch delim {
	case '{':
		m := make(map[string]any)
		seen := make(map[string]bool)
		for d.More() {
			if *remaining <= 0 {
				return nil, ErrInvalid
			}
			*remaining--
			key, err := d.Token()
			k, ok := key.(string)
			folded := strings.ToLower(k)
			if err != nil || !ok || !validString(k, maxKey) || seen[folded] {
				return nil, ErrInvalid
			}
			seen[folded] = true
			value, err := readValue(d, depth+1, remaining)
			if err != nil {
				return nil, err
			}
			m[k] = value
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') {
			return nil, ErrInvalid
		}
		return m, nil
	case '[':
		a := make([]any, 0)
		for d.More() {
			value, err := readValue(d, depth+1, remaining)
			if err != nil {
				return nil, err
			}
			a = append(a, value)
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return nil, ErrInvalid
		}
		return a, nil
	default:
		return nil, ErrInvalid
	}
}

func validString(s string, limit int) bool {
	return len(s) <= limit && !strings.ContainsRune(s, utf8.RuneError)
}
