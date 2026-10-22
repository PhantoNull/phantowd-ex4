// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package mcuproto

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
)

const (
	FrameStart = byte(0xfa)
	FrameEnd   = byte(0xfb)
	MaxFrame   = 15
)

var validLengths = map[int]bool{7: true, 13: true, 15: true}

// DecodedFrame reports a conservative observation of the vendor receive rules.
// DispatchKey retains bytes 1..3, even where some of those bytes are payload
// rather than fixed selectors. Known means a supported handler classification,
// not integrity, calibrated payload, hardware state or execution evidence.
type DecodedFrame struct {
	RawHex         string   `json:"raw_hex"`
	Length         int      `json:"length"`
	DispatchKey    [3]byte  `json:"dispatch_key"`
	Names          []string `json:"names,omitempty"`
	TemplateFourth []byte   `json:"template_fourth,omitempty"`
	Known          bool     `json:"known"`
	ChecksumStatus string   `json:"checksum_status"`
}

// DecodeReceive validates the researched envelope and classifies supported
// handlers using their length and fixed selector prefix. The stock 13-byte RTC
// branch has no selector validation and is deliberately left unclassified.
// Unsupported lengths retain only the observed length, never raw input.
func DecodeReceive(frame []byte) (DecodedFrame, error) {
	decoded := DecodedFrame{Length: len(frame), ChecksumStatus: "unknown-not-validated"}
	if !validLengths[len(frame)] {
		return decoded, fmt.Errorf("unsupported frame length %d", len(frame))
	}
	decoded.RawHex = hex.EncodeToString(frame)
	if frame[0] != FrameStart || frame[len(frame)-1] != FrameEnd {
		return decoded, errors.New("invalid frame boundary")
	}
	if bytes.IndexByte(frame[1:len(frame)-1], FrameStart) >= 0 {
		return decoded, errors.New("frame interrupted by a new start marker")
	}
	copy(decoded.DispatchKey[:], frame[1:4])
	for _, selector := range ReceiveSelectors {
		if matchesReceiveHandler(selector, frame) {
			decoded.Names = append(decoded.Names, selector.Name)
			decoded.TemplateFourth = append(decoded.TemplateFourth, selector.Template[3])
		}
	}
	decoded.Known = len(decoded.Names) != 0
	return decoded, nil
}

// matchesReceiveHandler is only called for an envelope already admitted above.
// ELF virtual-address anchors refer to the hash-identified final vendor
// up_read_daemon, not device registers or observations of MCU execution.
func matchesReceiveHandler(selector Selector, frame []byte) bool {
	if len(frame) == 13 {
		// 0x8eb4..0x9000 bypasses the table; bytes 1..3 cannot prove a name.
		return false
	}
	if (len(frame) == 15) != (selector.Name == "MCUVer") {
		// 0x892c..0x8980 admits only table class 3 for 15-byte frames.
		return false
	}
	switch selector.Name {
	case "GetThemister":
		// 0x8d8c..0x8dd8: fixed prefix, then sensor 1 (SATA) or 2 (main).
		// Other sensor values do not establish either sensor observation.
		return selector.Template[0] == frame[1] && selector.Template[1] == frame[2] && (frame[3] == 1 || frame[3] == 2)
	case "PWR_LOST", "APR_STAT", "WOL_STAT":
		// 0x8e08..0x8eb0: only byte 1 is compared; byte 2 is payload.
		return selector.Template[0] == frame[1]
	default:
		return selector.Template[0] == frame[1] && selector.Template[1] == frame[2] && selector.Template[2] == frame[3]
	}
}

// StreamStats records framing behavior without interpreting unknown payloads.
type StreamStats struct {
	Bytes      uint64 `json:"bytes"`
	NoiseBytes uint64 `json:"noise_bytes"`
	Frames     uint64 `json:"frames"`
	Malformed  uint64 `json:"malformed"`
	Truncated  uint64 `json:"truncated"`
	Known      uint64 `json:"known"`
	Unknown    uint64 `json:"unknown"`
}

// StreamDecoder separates a raw passive capture into the three frame lengths
// observed in the stock receive parser. It never produces transmit bytes.
type StreamDecoder struct {
	buffer []byte
	stats  StreamStats
}

// Push consumes an arbitrary capture chunk and returns complete frames.
func (decoder *StreamDecoder) Push(data []byte) []DecodedFrame {
	decoder.stats.Bytes += uint64(len(data))
	var frames []DecodedFrame
	for _, value := range data {
		// The stock receive loop restarts immediately on every 0xfa, even
		// before the 7/13/15-byte boundary tests. Never join an interrupted
		// prefix to a later frame or classify its bytes as a button event.
		if value == FrameStart {
			if len(decoder.buffer) != 0 {
				decoder.stats.Malformed++
			}
			decoder.buffer = append(decoder.buffer[:0], value)
			continue
		}
		if len(decoder.buffer) == 0 {
			decoder.stats.NoiseBytes++
			continue
		}

		decoder.buffer = append(decoder.buffer, value)
		length := len(decoder.buffer)
		if validLengths[length] && value == FrameEnd {
			frame, err := DecodeReceive(decoder.buffer)
			if err == nil {
				frames = append(frames, frame)
				decoder.stats.Frames++
				if frame.Known {
					decoder.stats.Known++
				} else {
					decoder.stats.Unknown++
				}
			}
			decoder.buffer = decoder.buffer[:0]
			continue
		}
		if length >= MaxFrame {
			decoder.stats.Malformed++
			decoder.buffer = decoder.buffer[:0]
		}
	}
	return frames
}

// Finalize marks a partial frame as truncated. Call it only at end-of-input.
func (decoder *StreamDecoder) Finalize() {
	if len(decoder.buffer) != 0 {
		decoder.stats.Truncated++
		decoder.buffer = decoder.buffer[:0]
	}
}

func (decoder *StreamDecoder) Stats() StreamStats {
	return decoder.stats
}

// State is a conservative simulator state. Only event counts and unambiguous
// push/release pairs are modeled; thermal, fan, power, ACK, and RTC payloads
// are never guessed.
type State struct {
	AppliedFrames uint64            `json:"applied_frames"`
	EventCounts   map[string]uint64 `json:"event_counts"`
	Buttons       map[string]bool   `json:"buttons"`
	LastKnown     string            `json:"last_known,omitempty"`
	UnknownFrames uint64            `json:"unknown_frames"`
}

func NewState() *State {
	return &State{
		EventCounts: make(map[string]uint64),
		Buttons: map[string]bool{
			"power": false, "reset": false, "function": false, "function2": false,
		},
	}
}

// Apply replays classification results into the conservative state model.
func (state *State) Apply(frame DecodedFrame) {
	state.AppliedFrames++
	if !frame.Known {
		state.UnknownFrames++
		return
	}
	for _, name := range frame.Names {
		state.EventCounts[name]++
		state.LastKnown = name
		switch name {
		case "PWRPush":
			state.Buttons["power"] = true
		case "PWRRelease":
			state.Buttons["power"] = false
		case "RSTPush":
			state.Buttons["reset"] = true
		case "RSTRelease":
			state.Buttons["reset"] = false
		case "FUNCPush":
			state.Buttons["function"] = true
		case "FUNCRelease":
			state.Buttons["function"] = false
		case "FUNC2Push":
			state.Buttons["function2"] = true
		case "FUNC2Release":
			state.Buttons["function2"] = false
		}
	}
}
