// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package mcuproto

import (
	"reflect"
	"testing"
)

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

func TestOversizedReceiveFrameDoesNotRetainRawInput(t *testing.T) {
	input := make([]byte, 4096)
	input[0], input[len(input)-1] = FrameStart, FrameEnd
	decoded, err := DecodeReceive(input)
	if err == nil {
		t.Fatal("oversized frame accepted")
	}
	if decoded.Length != len(input) || decoded.RawHex != "" {
		t.Fatal("oversized refusal retained raw input or lost the observed length")
	}
	if decoded.Known || len(decoded.Names) != 0 || len(decoded.TemplateFourth) != 0 ||
		decoded.DispatchKey != [3]byte{} || decoded.ChecksumStatus != "unknown-not-validated" {
		t.Fatal("oversized refusal returned selector or checksum evidence")
	}
}

func FuzzDecodeReceiveDiagnosticBounds(f *testing.F) {
	f.Add([]byte{FrameStart, 0x23, 0, 0, 0, 0, FrameEnd})
	f.Add([]byte{})
	f.Add(make([]byte, MaxFrame+1))
	f.Fuzz(func(t *testing.T, data []byte) {
		decoded, err := DecodeReceive(data)
		if decoded.Length != len(data) || len(decoded.RawHex) > 2*MaxFrame ||
			decoded.ChecksumStatus != "unknown-not-validated" {
			t.Fatal("receive diagnostics exceeded bounds or asserted checksum evidence")
		}
		switch len(data) {
		case 7, 13, 15:
			if len(decoded.RawHex) != 2*len(data) {
				t.Fatal("bounded frame diagnostics lost their bytes")
			}
		default:
			if err == nil || decoded.RawHex != "" || decoded.Known ||
				len(decoded.Names) != 0 || len(decoded.TemplateFourth) != 0 ||
				decoded.DispatchKey != [3]byte{} {
				t.Fatal("unsupported length returned raw input or classification")
			}
		}
	})
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

func TestStreamResynchronizesAtRestartMarker(t *testing.T) {
	push := []byte{FrameStart, 0x23, 0, 0, 0, 0, FrameEnd}
	input := append([]byte{FrameStart, 0x01, 0}, push...)
	decoder := &StreamDecoder{}
	frames := decoder.Push(input)
	decoder.Finalize()
	if len(frames) != 1 || !frames[0].Known || len(frames[0].Names) != 1 || frames[0].Names[0] != "PWRPush" {
		t.Fatalf("restart lost the complete following frame: %+v", frames)
	}
	stats := decoder.Stats()
	if stats.Bytes != uint64(len(input)) || stats.Frames != 1 || stats.Known != 1 || stats.Malformed != 1 || stats.Truncated != 0 || stats.NoiseBytes != 0 {
		t.Fatalf("restart accounting differs: %+v", stats)
	}
}

func TestDecodeReceiveRefusesRestartedButtonFrame(t *testing.T) {
	frame := []byte{FrameStart, 0x23, 0, 0, 0, FrameStart, FrameEnd}
	decoded, err := DecodeReceive(frame)
	if err == nil || decoded.Known || len(decoded.Names) != 0 || decoded.DispatchKey != [3]byte{} || decoded.ChecksumStatus != "unknown-not-validated" {
		t.Fatalf("interrupted bytes classified as a complete button frame: %+v, err=%v", decoded, err)
	}
	state := NewState()
	state.Apply(decoded)
	if state.Buttons["power"] || state.EventCounts["PWRPush"] != 0 {
		t.Fatal("rejected fragment changed the simulated power button")
	}
}

func TestStreamRestartAccountingAcrossEverySplit(t *testing.T) {
	for _, interrupted := range [][]byte{
		{FrameStart, 0x23, 0, 0, 0},
		{FrameStart, FrameStart, 0x23, 0, 0, 0},
		{FrameStart, 0x23, 0, 0, 0, FrameStart, FrameEnd},
	} {
		release := []byte{FrameStart, 0x2a, 0, 0, 0, 0, FrameEnd}
		input := append(append([]byte(nil), interrupted...), release...)
		for split := 0; split <= len(input); split++ {
			decoder := &StreamDecoder{}
			frames := append(decoder.Push(input[:split]), decoder.Push(input[split:])...)
			decoder.Finalize()
			state := NewState()
			for _, frame := range frames {
				state.Apply(frame)
			}
			stats := decoder.Stats()
			if len(frames) != 1 || state.EventCounts["PWRRelease"] != 1 || state.EventCounts["PWRPush"] != 0 || state.Buttons["power"] ||
				stats.Frames != 1 || stats.Unknown != 0 || stats.Truncated != 0 || stats.Bytes != uint64(len(input)) {
				t.Fatalf("split %d invented an event or lost the following frame: %+v %+v", split, stats, state)
			}
			wantMalformed := uint64(1)
			if interrupted[1] == FrameStart || len(interrupted) == 7 {
				wantMalformed = 2
			}
			if stats.Malformed != wantMalformed {
				t.Fatalf("split %d restart count=%d want=%d", split, stats.Malformed, wantMalformed)
			}
		}
	}
}

func TestDecodeReceiveRejectsEveryInteriorStartPosition(t *testing.T) {
	for _, length := range []int{7, 13, 15} {
		for position := 1; position < length-1; position++ {
			frame := make([]byte, length)
			frame[0], frame[position], frame[length-1] = FrameStart, FrameStart, FrameEnd
			decoded, err := DecodeReceive(frame)
			if err == nil || decoded.Known || len(decoded.Names) != 0 || len(decoded.RawHex) != 2*length || decoded.ChecksumStatus != "unknown-not-validated" {
				t.Fatalf("interior start at %d/%d was admitted or lost bounded diagnostics", position, length)
			}
		}
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
		frames := decoder.Push(data)
		for _, frame := range frames {
			if _, err := DecodeReceive(mustDecodeHex(t, frame.RawHex)); err != nil {
				t.Fatalf("stream returned invalid frame: %v", err)
			}
		}
		decoder.Finalize()
		if len(decoder.buffer) != 0 {
			t.Fatal("finalize retained buffered input")
		}
		split := len(data) / 2
		fragmented := &StreamDecoder{}
		other := append(fragmented.Push(data[:split]), fragmented.Push(data[split:])...)
		fragmented.Finalize()
		if !reflect.DeepEqual(frames, other) || decoder.Stats() != fragmented.Stats() {
			t.Fatal("chunk boundaries changed framing or diagnostics")
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
