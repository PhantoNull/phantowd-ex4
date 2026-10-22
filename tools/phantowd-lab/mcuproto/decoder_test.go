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

func TestDecodeReceiveDoesNotClassifyLongButtonFrames(t *testing.T) {
	for _, length := range []int{13, 15} {
		frame := make([]byte, length)
		frame[0], frame[1], frame[length-1] = FrameStart, 0x23, FrameEnd
		decoded, err := DecodeReceive(frame)
		if err != nil {
			t.Fatal(err)
		}
		if decoded.Known || len(decoded.Names) != 0 || len(decoded.TemplateFourth) != 0 {
			t.Fatalf("%d-byte envelope invented a seven-byte button event: %+v", length, decoded)
		}
		state := NewState()
		state.Apply(decoded)
		if state.Buttons["power"] || len(state.EventCounts) != 0 || state.UnknownFrames != 1 {
			t.Fatal("unclassified long frame changed the button simulator")
		}
	}
}

func TestDecodeReceiveThermistorSensorDispatch(t *testing.T) {
	for _, sensor := range []byte{1, 2} {
		// Byte 3 selects the sensor, not a third fixed selector byte.
		// Byte 5 is retained raw: no calibrated temperature is asserted.
		frame := []byte{FrameStart, 3, 8, sensor, 0, 42, FrameEnd}
		decoded, err := DecodeReceive(frame)
		if err != nil || !decoded.Known || !reflect.DeepEqual(decoded.Names, []string{"GetThemister"}) {
			t.Fatalf("sensor %d not recognized: %+v, err=%v", sensor, decoded, err)
		}
		if decoded.DispatchKey != [3]byte{3, 8, sensor} || decoded.ChecksumStatus != "unknown-not-validated" {
			t.Fatal("sensor dispatch lost raw bytes or asserted checksum evidence")
		}
	}
}

func TestDecodeReceiveStatusPayloadIsNotSelector(t *testing.T) {
	for _, test := range []struct {
		prefix byte
		name   string
	}{{0x40, "PWR_LOST"}, {0x41, "APR_STAT"}, {0x42, "WOL_STAT"}} {
		frame := []byte{FrameStart, test.prefix, 7, 9, 0, 0, FrameEnd}
		decoded, err := DecodeReceive(frame)
		if err != nil || !decoded.Known || !reflect.DeepEqual(decoded.Names, []string{test.name}) {
			t.Fatalf("status payload not recognized: %+v, err=%v", decoded, err)
		}
	}
}

func TestReceiveCatalogLengthSeparation(t *testing.T) {
	for _, selector := range ReceiveSelectors {
		for _, length := range []int{7, 13, 15} {
			frame := make([]byte, length)
			frame[0], frame[length-1] = FrameStart, FrameEnd
			copy(frame[1:4], selector.Template[:3])
			decoded, err := DecodeReceive(frame)
			if err != nil {
				t.Fatal(err)
			}
			wantKnown := length == 7 && selector.Name != "MCUVer" && selector.Name != "GetThemister" ||
				length == 15 && selector.Name == "MCUVer"
			if decoded.Known != wantKnown {
				t.Fatalf("%s length %d known=%v want=%v", selector.Name, length, decoded.Known, wantKnown)
			}
			if wantKnown && (!reflect.DeepEqual(decoded.Names, []string{selector.Name}) ||
				!reflect.DeepEqual(decoded.TemplateFourth, []byte{selector.Template[3]})) {
				t.Fatalf("catalog metadata changed: %+v", decoded)
			}
			if !wantKnown && (len(decoded.Names) != 0 || len(decoded.TemplateFourth) != 0) {
				t.Fatalf("unclassified frame retained handler metadata: %+v", decoded)
			}
		}
	}
}

func TestThermistorSensorAndRawPayloadBoundaries(t *testing.T) {
	for sensor := 0; sensor <= 255; sensor++ {
		for _, payload := range []byte{0, 42, 249, FrameEnd, 255} {
			frame := []byte{FrameStart, 3, 8, byte(sensor), 0x91, payload, FrameEnd}
			decoded, err := DecodeReceive(frame)
			if sensor == int(FrameStart) {
				if err == nil || decoded.Known {
					t.Fatal("sensor start marker bypassed framing")
				}
				continue
			}
			if err != nil || decoded.Known != (sensor == 1 || sensor == 2) ||
				decoded.ChecksumStatus != "unknown-not-validated" {
				t.Fatalf("sensor %d payload %d misclassified: %+v, err=%v", sensor, payload, decoded, err)
			}
		}
	}
	for _, prefix := range [][2]byte{{2, 8}, {3, 9}, {4, 8}} {
		decoded, err := DecodeReceive([]byte{FrameStart, prefix[0], prefix[1], 1, 0, 42, FrameEnd})
		if err != nil || decoded.Known {
			t.Fatal("thermistor prefix mismatch admitted")
		}
	}
}

func TestStatusPayloadBoundariesDoNotChangeButtons(t *testing.T) {
	for _, prefix := range []byte{0x40, 0x41, 0x42} {
		for value := 0; value <= 255; value++ {
			frame := []byte{FrameStart, prefix, byte(value), byte(255 - value), 0x91, 0x92, FrameEnd}
			decoded, err := DecodeReceive(frame)
			interrupted := value == int(FrameStart) || 255-value == int(FrameStart)
			if interrupted {
				if err == nil || decoded.Known {
					t.Fatal("status payload start marker bypassed framing")
				}
				continue
			}
			if err != nil || !decoded.Known || len(decoded.Names) != 1 || decoded.ChecksumStatus != "unknown-not-validated" {
				t.Fatalf("status %x payload %d lost classification: %+v, err=%v", prefix, value, decoded, err)
			}
			state := NewState()
			state.Apply(decoded)
			for button, pressed := range state.Buttons {
				if pressed {
					t.Fatalf("status changed simulated %s button", button)
				}
			}
		}
	}
}

func TestStreamHandlerClassificationAcrossEverySplit(t *testing.T) {
	// Start with a valid button press, then long envelopes containing the
	// release selector. Neither long envelope may release the held button.
	input := []byte{FrameStart, 0x23, 0, 0, 0, 0, FrameEnd}
	for _, length := range []int{13, 15} {
		frame := make([]byte, length)
		frame[0], frame[1], frame[length-1] = FrameStart, 0x2a, FrameEnd
		input = append(input, frame...)
	}
	input = append(input, FrameStart, 3, 8, 2, 0, 42, FrameEnd)
	input = append(input, FrameStart, 0x41, 1, 2, 0, 0, FrameEnd)
	for split := 0; split <= len(input); split++ {
		decoder := &StreamDecoder{}
		frames := append(decoder.Push(input[:split]), decoder.Push(input[split:])...)
		decoder.Finalize()
		state := NewState()
		for _, frame := range frames {
			state.Apply(frame)
		}
		stats := decoder.Stats()
		if len(frames) != 5 || stats.Known != 3 || stats.Unknown != 2 || stats.Malformed != 0 || stats.Truncated != 0 ||
			!state.Buttons["power"] || state.EventCounts["PWRRelease"] != 0 || state.EventCounts["GetThemister"] != 1 ||
			state.EventCounts["APR_STAT"] != 1 || state.UnknownFrames != 2 {
			t.Fatalf("split %d changed handler/state accounting: %+v %+v", split, stats, state)
		}
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
	f.Add([]byte{FrameStart, 3, 8, 1, 0, 42, FrameEnd})
	f.Add([]byte{FrameStart, 0x41, 1, 2, 0, 0, FrameEnd})
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
			if len(data) == 13 && (decoded.Known || len(decoded.Names) != 0 || len(decoded.TemplateFourth) != 0) {
				t.Fatal("unvalidated RTC branch acquired a catalog identity")
			}
			if len(data) == 15 && decoded.Known && !reflect.DeepEqual(decoded.Names, []string{"MCUVer"}) {
				t.Fatal("long frame acquired a non-version handler")
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
	f.Add([]byte{FrameStart, 3, 8, 2, 0, 42, FrameEnd})
	f.Add([]byte{FrameStart, 0x42, 1, 2, 0, 0, FrameEnd})
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
