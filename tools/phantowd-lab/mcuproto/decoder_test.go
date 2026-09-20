// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package mcuproto

import "testing"

func TestCatalogCounts(t *testing.T) {
	if len(TransmitSelectors) != 82 {
		t.Fatalf("transmit selector count = %d, want 82", len(TransmitSelectors))
	}
	if len(ReceiveSelectors) != 38 {
		t.Fatalf("receive selector count = %d, want 38", len(ReceiveSelectors))
	}
}

func TestDecodeReceive(t *testing.T) {
	frame := []byte{FrameStart, 0x23, 0x00, 0x00, 0x00, 0x00, FrameEnd}
	decoded, err := DecodeReceive(frame)
	if err != nil {
		t.Fatal(err)
	}
	if !decoded.Known || len(decoded.Names) != 1 || decoded.Names[0] != "PWRPush" {
		t.Fatalf("unexpected decode: %+v", decoded)
	}
	if decoded.ChecksumStatus != "unknown-not-validated" {
		t.Fatalf("checksum status = %q", decoded.ChecksumStatus)
	}
}

func TestDecodeRejectsInvalidEnvelope(t *testing.T) {
	for _, frame := range [][]byte{
		{FrameStart, 1, 2, FrameEnd},
		{0, 0x23, 0, 0, 0, 0, FrameEnd},
		{FrameStart, 0x23, 0, 0, 0, 0, 0},
	} {
		if _, err := DecodeReceive(frame); err == nil {
			t.Fatalf("accepted invalid frame %x", frame)
		}
	}
}

func TestStreamReplayAndButtonState(t *testing.T) {
	decoder := &StreamDecoder{}
	state := NewState()
	push := []byte{FrameStart, 0x23, 0, 0, 0, 0, FrameEnd}
	release := []byte{FrameStart, 0x2a, 0, 0, 0, 0, FrameEnd}
	input := append([]byte{0xde, 0xad}, push...)
	input = append(input, release...)
	for _, frame := range decoder.Push(input[:9]) {
		state.Apply(frame)
	}
	for _, frame := range decoder.Push(input[9:]) {
		state.Apply(frame)
	}
	decoder.Finalize()
	stats := decoder.Stats()
	if stats.Frames != 2 || stats.NoiseBytes != 2 || stats.Malformed != 0 || stats.Truncated != 0 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
	if state.Buttons["power"] || state.EventCounts["PWRPush"] != 1 || state.EventCounts["PWRRelease"] != 1 {
		t.Fatalf("unexpected state: %+v", state)
	}
}

func TestStreamFaultAccounting(t *testing.T) {
	decoder := &StreamDecoder{}
	decoder.Push([]byte{FrameStart, 1, 2})
	decoder.Finalize()
	decoder.Push([]byte{FrameStart, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14})
	stats := decoder.Stats()
	if stats.Truncated != 1 || stats.Malformed != 1 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
}

func FuzzStreamDecoder(f *testing.F) {
	f.Add([]byte{FrameStart, 0x30, 0, 0, 0, 0, FrameEnd})
	f.Add([]byte{0, 1, 2, 3})
	f.Fuzz(func(t *testing.T, data []byte) {
		decoder := &StreamDecoder{}
		for _, frame := range decoder.Push(data) {
			if _, err := DecodeReceive(mustDecodeHex(t, frame.RawHex)); err != nil {
				t.Fatalf("stream returned invalid frame: %v", err)
			}
		}
		decoder.Finalize()
		if len(decoder.buffer) != 0 {
			t.Fatal("finalize retained buffered input")
		}
	})
}

func mustDecodeHex(t *testing.T, value string) []byte {
	t.Helper()
	if len(value)%2 != 0 {
		t.Fatal("odd hex length")
	}
	result := make([]byte, len(value)/2)
	for i := range result {
		var high, low byte
		for index, target := range []*byte{&high, &low} {
			character := value[2*i+index]
			switch {
			case character >= '0' && character <= '9':
				*target = character - '0'
			case character >= 'a' && character <= 'f':
				*target = character - 'a' + 10
			default:
				t.Fatalf("invalid hex %q", value)
			}
		}
		result[i] = high<<4 | low
	}
	return result
}
