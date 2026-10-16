// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package frontpaneltext prepares bounded plain text in memory. It has no
// controller, transport, frame encoder, device access or startup integration.
package frontpaneltext

import "errors"

var (
	ErrInvalid = errors.New("invalid front-panel text")
	ErrPrivate = errors.New("front-panel text is internal")
)

// MaxPayloadBytes is a representation ceiling from the selected legacy
// builders' one-byte length, not the EX4's qualified LCD width or MCU capacity.
const MaxPayloadBytes = 255

// Text retains a nonempty printable-ASCII request, not displayed/acknowledged
// state. The zero value is invalid. No JSON representation is provided.
type Text struct{ value string }

func (t Text) Value() (string, bool)      { return t.value, t.value != "" }
func (Text) MarshalJSON() ([]byte, error) { return nil, ErrPrivate }
func (*Text) UnmarshalJSON([]byte) error  { return ErrPrivate }

// Prepare requires a caller-declared byte limit in 1..MaxPayloadBytes and
// accepts only nonempty bytes 0x20..0x7e. It preserves spaces exactly and never
// truncates, substitutes, transliterates, escapes or interprets numbers.
//
// The limit and ASCII repertoire are NOT independently established hardware
// capabilities. A future trusted profile must qualify them before any use on
// a device. In particular neither the legacy table's value20 nor a successful
// preparation establishes LCD width, glyphs, framing integrity, command
// acceptance, applied fan speed, temperature or physical controller state.
// Empty text cannot stand for a clear command without a separate contract.
//
// Length is checked before scanning; rejected input is not retained in an
// error or result. Work is bounded by255 bytes, with no per-call allocation.
func Prepare(value string, maxBytes int) (Text, error) {
	if maxBytes < 1 || maxBytes > MaxPayloadBytes || len(value) == 0 || len(value) > maxBytes {
		return Text{}, ErrInvalid
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x20 || value[i] > 0x7e {
			return Text{}, ErrInvalid
		}
	}
	return Text{value: value}, nil
}
