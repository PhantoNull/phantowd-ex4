// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package mcuproto

import (
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

// DecodedFrame reports only evidence established by the vendor parser: frame
// boundaries, length class, first-three-byte dispatch key, and catalog match.
// Payload/checksum semantics are intentionally left unassigned.
type DecodedFrame struct {
	RawHex         string   `json:"raw_hex"`
	Length         int      `json:"length"`
	DispatchKey    [3]byte  `json:"dispatch_key"`
	Names          []string `json:"names,omitempty"`
	TemplateFourth []byte   `json:"template_fourth,omitempty"`
	Known          bool     `json:"known"`
	ChecksumStatus string   `json:"checksum_status"`
}

// DecodeReceive validates the known envelope and performs the same
// first-three-byte selector classification established by static analysis.
func DecodeReceive(frame []byte) (DecodedFrame, error) {
	decoded := DecodedFrame{RawHex: hex.EncodeToString(frame), Length: len(frame), ChecksumStatus: "unknown-not-validated"}
	if !validLengths[len(frame)] {
		return decoded, fmt.Errorf("unsupported frame length %d", len(frame))
	}
	if frame[0] != FrameStart || frame[len(frame)-1] != FrameEnd {
		return decoded, errors.New("invalid frame boundary")
	}
	copy(decoded.DispatchKey[:], frame[1:4])
	for _, selector := range ReceiveSelectors {
		if selector.Template[0] == frame[1] && selector.Template[1] == frame[2] && selector.Template[2] == frame[3] {
			decoded.Names = append(decoded.Names, selector.Name)
			decoded.TemplateFourth = append(decoded.TemplateFourth, selector.Template[3])
		}
	}
	decoded.Known = len(decoded.Names) != 0
	return decoded, nil
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
		if len(decoder.buffer) == 0 {
			if value != FrameStart {
				decoder.stats.NoiseBytes++
				continue
			}
			decoder.buffer = append(decoder.buffer, value)
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
			if value == FrameStart {
				decoder.buffer = append(decoder.buffer, value)
			}
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
