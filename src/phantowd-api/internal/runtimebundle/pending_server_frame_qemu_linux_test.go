//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
)

// An independently specified byte layout, not a native C struct dump.
func pendingServerFrameExampleQEMU(sequence uint32) []byte {
	frame := make([]byte, 88)
	copy(frame, "PWDOPEN\x00")
	binary.LittleEndian.PutUint16(frame[8:], 1)
	binary.LittleEndian.PutUint16(frame[10:], 72)
	binary.LittleEndian.PutUint32(frame[12:], sequence)
	for index, value := range []uint64{4294967297, 123, 456, 7777, 8, 4294967399, 987654321} {
		binary.LittleEndian.PutUint64(frame[16+index*8:], value)
	}
	for index, value := range []uint32{21, 1002, 0, 4294967295} {
		binary.LittleEndian.PutUint32(frame[72+index*4:], value)
	}
	return frame
}

func TestPendingServerOpenFrames(t *testing.T) {
	for _, sequence := range []uint32{1, 2} {
		observed, err := decodePendingServerOpenFrameQEMU(pendingServerFrameExampleQEMU(sequence), sequence)
		if err != nil || observed.session != 4294967297 || observed.persistent != 123 ||
			observed.volatile != 456 || observed.shareFileID != 7777 || observed.device != 8 ||
			observed.inode != 4294967399 || observed.workerUnique != 987654321 ||
			observed.tree != 21 || observed.workerPID != 1002 || observed.workerTask != 0 ||
			observed.workerVNN != 4294967295 {
			t.Fatal("fixed private frame lost or confused an ID domain")
		}
	}
}

func TestPendingServerOpenFramesRefuseMalformed(t *testing.T) {
	refuse := func(frame []byte, sequence uint32) {
		t.Helper()
		got, err := decodePendingServerOpenFrameQEMU(frame, sequence)
		if !errors.Is(err, ErrMismatch) || got != (pendingServerOpenMetadataQEMU{}) || err.Error() != ErrMismatch.Error() {
			t.Fatal("malformed private frame published metadata or an unredacted error")
		}
	}
	base := pendingServerFrameExampleQEMU(1)
	for size := 0; size < len(base); size++ {
		refuse(base[:size], 1)
	}
	refuse(append(append([]byte(nil), base...), 0), 1)
	refuse(append(append([]byte(nil), base...), base...), 1)
	for index := 0; index < 16; index++ {
		changed := append([]byte(nil), base...)
		changed[index] ^= 0x80
		refuse(changed, 1)
	}
	for _, sequence := range []uint32{0, 2, 3, math.MaxUint32} {
		refuse(base, sequence)
	}
	for _, offset := range []int{16, 24, 32, 40, 64} {
		for _, value := range []uint64{0, math.MaxUint64} {
			changed := append([]byte(nil), base...)
			binary.LittleEndian.PutUint64(changed[offset:], value)
			refuse(changed, 1)
		}
	}
	for _, offset := range []int{48, 56} {
		changed := append([]byte(nil), base...)
		binary.LittleEndian.PutUint64(changed[offset:], 0)
		refuse(changed, 1)
	}
	for _, value := range []uint32{0, math.MaxUint32} {
		changed := append([]byte(nil), base...)
		binary.LittleEndian.PutUint32(changed[72:], value)
		refuse(changed, 1)
	}
	for _, value := range []uint32{0, 1, math.MaxInt32 + 1, math.MaxUint32} {
		changed := append([]byte(nil), base...)
		binary.LittleEndian.PutUint32(changed[76:], value)
		refuse(changed, 1)
	}
	for _, offset := range []int{80, 84} {
		changed := append([]byte(nil), base...)
		changed[offset] ^= 1
		refuse(changed, 1)
	}
}

func TestPendingServerOpenMatching(t *testing.T) {
	status, err := parsePendingStatusQEMU([]byte(pendingStatusFixtureQEMU()))
	if err != nil {
		t.Fatal(err)
	}
	frame := pendingServerFrameExampleQEMU(1)
	session, _ := strconv.ParseUint(status.session, 10, 64)
	binary.LittleEndian.PutUint64(frame[16:], session)
	binary.LittleEndian.PutUint64(frame[40:], status.shareFileID)
	binary.LittleEndian.PutUint64(frame[56:], status.inode)
	observed, err := decodePendingServerOpenFrameQEMU(frame, 1)
	if err != nil {
		t.Fatal(err)
	}
	client := processowner.PendingHandleObservationQEMU{
		SessionID: session, TreeID: 21, PersistentID: 123, VolatileID: 456,
	}
	if matchPendingServerOpenMetadataQEMU(observed, status, client) != nil {
		t.Fatal("independent STATUS/client metadata did not match their own ID domains")
	}
	for _, offset := range []int{16, 24, 32, 40, 48, 56, 64, 72, 76} {
		changed := append([]byte(nil), frame...)
		changed[offset] ^= 1
		got, err := decodePendingServerOpenFrameQEMU(changed, 1)
		if err == nil && matchPendingServerOpenMetadataQEMU(got, status, client) == nil {
			t.Fatal("one changed ID domain matched the original observations")
		}
	}
	wrongClient := client
	wrongClient.PersistentID, wrongClient.VolatileID = observed.shareFileID, observed.shareFileID
	if matchPendingServerOpenMetadataQEMU(observed, status, wrongClient) == nil {
		t.Fatal("share-mode generation substituted for remote IDs")
	}
	wrongStatus := status
	wrongStatus.shareFileID = client.PersistentID
	if matchPendingServerOpenMetadataQEMU(observed, wrongStatus, client) == nil {
		t.Fatal("remote ID substituted for server share-mode generation")
	}
	for _, malformed := range []pendingStatusQEMU{
		{}, {server: status.server, session: "0" + status.session, tree: status.tree,
			device: status.device, inode: status.inode, shareFileID: status.shareFileID},
	} {
		if err := matchPendingServerOpenMetadataQEMU(observed, malformed, client); err != ErrMismatch {
			t.Fatal("missing/noncanonical STATUS was accepted or exposed metadata")
		}
	}
	if matchPendingServerOpenMetadataQEMU(pendingServerOpenMetadataQEMU{}, status, client) != ErrMismatch ||
		matchPendingServerOpenMetadataQEMU(observed, status, processowner.PendingHandleObservationQEMU{}) != ErrMismatch {
		t.Fatal("missing observation accepted")
	}
	for index := 0; index < 9; index++ {
		changed := status
		switch index {
		case 0:
			changed.session = "0" + changed.session
		case 1:
			changed.tree = "0" + changed.tree
		case 2:
			changed.shareFileID++
		case 3:
			changed.device++
		case 4:
			changed.inode++
		case 5:
			changed.server.PID = "0" + changed.server.PID
		case 6:
			changed.server.TaskID = "1"
		case 7:
			changed.server.VNN = "0"
		case 8:
			changed.server.UniqueID = "0" + changed.server.UniqueID
		}
		if matchPendingServerOpenMetadataQEMU(observed, changed, client) != ErrMismatch {
			t.Fatal("changed/noncanonical independent STATUS field accepted")
		}
	}
	for index := 0; index < 4; index++ {
		changed := client
		switch index {
		case 0:
			changed.SessionID++
		case 1:
			changed.TreeID++
		case 2:
			changed.PersistentID++
		case 3:
			changed.VolatileID++
		}
		if matchPendingServerOpenMetadataQEMU(observed, status, changed) != ErrMismatch {
			t.Fatal("changed original client field accepted")
		}
	}
}

func TestPendingServerOpenFramesConcurrent(t *testing.T) {
	frame := pendingServerFrameExampleQEMU(1)
	expected, err := decodePendingServerOpenFrameQEMU(frame, 1)
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	for range 32 {
		workers.Go(func() {
			for range 20 {
				got, err := decodePendingServerOpenFrameQEMU(frame, 1)
				if err != nil || got != expected {
					t.Error("read-only shared bytes changed across concurrent decodes")
				}
			}
		})
	}
	workers.Wait()
}

func TestPendingServerOpenFramesCaptureBound(t *testing.T) {
	var capture pendingServerFrameTestCaptureQEMU
	if n, err := capture.Write(make([]byte, 176)); n != 176 || err != nil {
		t.Fatal("two complete frames not captured")
	}
	if n, err := capture.Write([]byte{1}); n != 1 || err != nil || capture.used != 177 {
		t.Fatal("overflow sentinel was not bounded")
	}
	before := capture
	if n, err := capture.Write([]byte{2}); n != 0 || err != io.ErrShortWrite || capture != before {
		t.Fatal("excess bytes changed the captured frame or were accepted")
	}
}

type pendingServerFrameTestCaptureQEMU struct {
	data [177]byte
	used int
}

func (b *pendingServerFrameTestCaptureQEMU) Write(data []byte) (int, error) {
	if len(data) > len(b.data)-b.used {
		return 0, io.ErrShortWrite
	}
	copy(b.data[b.used:], data)
	b.used += len(data)
	return len(data), nil
}

func TestPendingServerOpenCFrameQEMU(t *testing.T) {
	if os.Getenv("PHANTOWD_SERVER_OPEN_WIRE_FIXTURE") != "1" {
		t.Skip("explicit disposable ARM guest only; no native producer is inferred")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/sbin/phantowd-server-open-source-test", "--frames")
	var output, diagnostic pendingServerFrameTestCaptureQEMU
	cmd.Stdout, cmd.Stderr = &output, &diagnostic
	if err := cmd.Run(); err != nil || output.used != 176 || diagnostic.used != 0 {
		t.Fatal("fixed C producer refused or exceeded the private frame contract")
	}
	first, firstErr := decodePendingServerOpenFrameQEMU(output.data[:88], 1)
	second, secondErr := decodePendingServerOpenFrameQEMU(output.data[88:176], 2)
	if firstErr != nil || secondErr != nil || first != second ||
		first.session != 42 || first.tree != 21 || first.persistent != 123 || first.volatile != 456 ||
		first.shareFileID != 7777 || first.workerUnique != 999 || first.workerPID != uint32(cmd.Process.Pid) {
		t.Fatal("actual ARM C bytes lost field domains or producer PID when decoded in Go")
	}
	if _, err := decodePendingServerOpenFrameQEMU(output.data[:88], 2); err != ErrMismatch {
		t.Fatal("first packet substituted for the second observation")
	}
	fmt.Println("PHANTOWD_SERVER_OPEN_WIRE_READY frames=2 c_to_go=true bounded=true synthetic_open=true active_worker=false proof=false scope=qemu-only")
}

func FuzzPendingServerOpenFrame(f *testing.F) {
	f.Add(pendingServerFrameExampleQEMU(1), uint32(1))
	f.Add(pendingServerFrameExampleQEMU(2), uint32(2))
	f.Add([]byte{}, uint32(0))
	f.Fuzz(func(t *testing.T, frame []byte, sequence uint32) {
		got, err := decodePendingServerOpenFrameQEMU(frame, sequence)
		if err != nil {
			if err != ErrMismatch || got != (pendingServerOpenMetadataQEMU{}) {
				t.Fatal("refusal exposed a partial observation")
			}
			return
		}
		if len(frame) != 88 || (sequence != 1 && sequence != 2) || !got.valid() ||
			binary.LittleEndian.Uint64(frame[16:]) != got.session ||
			binary.LittleEndian.Uint64(frame[40:]) != got.shareFileID ||
			binary.LittleEndian.Uint64(frame[56:]) != got.inode ||
			binary.LittleEndian.Uint32(frame[76:]) != got.workerPID {
			t.Fatal("successful decode changed bytes, domains or validity")
		}
	})
}
