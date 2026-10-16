// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package smartreport

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

var ErrIdentity = errors.New("SMART report identity refused")

// ATAReportComparison holds separately supplied expected report fields. It is
// immutable private data, NOT stable media identity, provenance or authority.
// The future provider must qualify where these expected values came from.
type ATAReportComparison struct {
	serial string
	wwn    uint64
}

func NewATAReportComparison(serial string, wwn uint64) (ATAReportComparison, error) {
	p := ATAReportComparison{serial: serial, wwn: wwn}
	if !p.Valid() {
		return ATAReportComparison{}, ErrIdentity
	}
	return p, nil
}

func (p ATAReportComparison) Valid() bool { return ataSerial(p.serial) && p.wwn>>60 == 5 }
func (p ATAReportComparison) Parse(data []byte, observedExit int) (Observation, error) {
	return ParseMatchingATAIdentity(data, observedExit, p.serial, p.wwn)
}
func (ATAReportComparison) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "ata-report-comparison{private}")
}
func (ATAReportComparison) MarshalJSON() ([]byte, error) { return nil, ErrPrivate }
func (*ATAReportComparison) UnmarshalJSON([]byte) error  { return ErrPrivate }

// ParseMatchingATAIdentity additionally requires an exact ATA serial and an
// NAA-5 WWN, both supplied by a separately trusted caller. It does not discover,
// normalize or retain identifiers. Missing evidence has no weaker fallback.
// Matching text is NOT provenance, stable identity, a device lease or command
// authority: a future provider must still pin and qualify the actual source,
// runtime, transport and complete-census generation before and after capture.
// No product startup uses this parser or supplies a physical command backend.
func ParseMatchingATAIdentity(data []byte, observedExit int, serial string, wwn uint64) (Observation, error) {
	if !ataSerial(serial) || wwn>>60 != 5 {
		return Observation{}, ErrIdentity
	}
	root, err := readReport(data, observedExit)
	if err != nil {
		return Observation{}, err
	}
	report, err := parseReport(root, observedExit)
	if err != nil {
		return Observation{}, err
	}
	device, ok := root["device"].(map[string]any)
	if !ok || device["protocol"] != "ATA" {
		return Observation{}, ErrIdentity
	}
	gotSerial, ok := root["serial_number"].(string)
	if !ok || !ataSerial(gotSerial) || gotSerial != serial {
		return Observation{}, ErrIdentity
	}
	fields, ok := root["wwn"].(map[string]any)
	if !ok {
		return Observation{}, ErrIdentity
	}
	naa, e1 := identityInteger(fields["naa"], 4)
	oui, e2 := identityInteger(fields["oui"], 24)
	id, e3 := identityInteger(fields["id"], 36)
	if e1 != nil || e2 != nil || e3 != nil || naa != 5 || naa<<60|oui<<36|id != wwn {
		return Observation{}, ErrIdentity
	}
	return report, nil
}

// Narrow comparison profile, not a general ATA string decoder. In particular,
// never trim, case-fold or otherwise join differently represented identities.
func ataSerial(s string) bool {
	if len(s) == 0 || len(s) > 20 || strings.TrimSpace(s) != s {
		return false
	}
	for _, c := range s {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

func identityInteger(value any, bits int) (uint64, error) {
	number, ok := value.(json.Number)
	if !ok || number == "" {
		return 0, ErrIdentity
	}
	for _, c := range string(number) {
		if c < '0' || c > '9' {
			return 0, ErrIdentity
		}
	}
	n, err := strconv.ParseUint(string(number), 10, bits)
	if err != nil {
		return 0, ErrIdentity
	}
	return n, nil
}
