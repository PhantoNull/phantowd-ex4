//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/frontpaneltext"
)

// Invented profile, not EX4 glyph/width qualification. No device or transport.
func exerciseQEMUFrontPanelText() error {
	for b := 0; b <= 255; b++ {
		value := string([]byte{byte(b)})
		text, err := frontpaneltext.Prepare(value, 1)
		got, valid := text.Value()
		if b >= 0x20 && b <= 0x7e {
			if err != nil || !valid || got != value {
				return errors.New("synthetic front-panel printable byte rejected")
			}
		} else if !errors.Is(err, frontpaneltext.ErrInvalid) || valid || got != "" {
			return errors.New("synthetic front-panel malformed byte accepted")
		}
	}
	value := strings.Repeat("x", 255)
	text, err := frontpaneltext.Prepare(value, 255)
	got, valid := text.Value()
	if err != nil || !valid || got != value {
		return errors.New("synthetic front-panel inclusive limit rejected")
	}
	for _, tc := range []struct {
		value string
		limit int
	}{
		{"", 20}, {"NAS", 0}, {"NAS", -1}, {"NAS", 256},
		{value + "x", 255}, {"xx", 1}, {"caffè", 20}, {"a\nb", 20},
	} {
		failed, err := frontpaneltext.Prepare(tc.value, tc.limit)
		got, valid := failed.Value()
		if !errors.Is(err, frontpaneltext.ErrInvalid) || valid || got != "" || failed != (frontpaneltext.Text{}) {
			return errors.New("synthetic front-panel invalid input retained")
		}
	}
	if _, err := json.Marshal(text); !errors.Is(err, frontpaneltext.ErrPrivate) {
		return errors.New("synthetic front-panel private text serialized")
	}
	return nil
}
