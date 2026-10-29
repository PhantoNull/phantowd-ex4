//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package revisionstore

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

func nasWriterEvent(mask, cookie uint32, name string) []byte {
	size := (len(name) + 4) &^ 3
	b := make([]byte, unix.SizeofInotifyEvent+size)
	for i, value := range []uint32{1, mask, cookie, uint32(size)} {
		binary.NativeEndian.PutUint32(b[i*4:], value)
	}
	copy(b[unix.SizeofInotifyEvent:], name)
	return b
}

func TestNASWriterEventsRefuseUnterminatedName(t *testing.T) {
	b := nasWriterEvent(unix.IN_CREATE, 0, ".nas-services.pending")
	b = b[:unix.SizeofInotifyEvent+len(".nas-services.pending")]
	binary.NativeEndian.PutUint32(b[12:], uint32(len(".nas-services.pending")))
	for _, event := range [][]byte{
		nasWriterEvent(unix.IN_MODIFY, 0, ".nas-services.pending"),
		nasWriterEvent(unix.IN_CLOSE_WRITE, 0, ".nas-services.pending"),
		nasWriterEvent(unix.IN_MOVED_FROM, 7, ".nas-services.pending"),
		nasWriterEvent(unix.IN_MOVED_TO, 7, "nas-services.json"),
	} {
		b = append(b, event...)
	}
	e := nasWriterEvents{descriptor: 1, role: "nas-services.json"}
	if e.consume(b) && e.complete() {
		t.Fatal("unterminated event name accepted")
	}
}

func nasWriterEventFixture(t *testing.T) (*os.File, int, int) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	if err := unix.Flock(int(root.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	watch, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(watch) })
	wd, err := unix.InotifyAddWatch(watch, "/proc/self/fd/"+strconv.Itoa(int(root.Fd())), policyEvents|unix.IN_ONLYDIR)
	if err != nil {
		t.Fatal(err)
	}
	return root, watch, wd
}

func TestNASWriterEventsAcceptActualStagesAndReceiptRetirement(t *testing.T) {
	root, watch, wd := nasWriterEventFixture(t)
	for range 2 {
		for _, role := range []string{".nas-services.base", ".nas-services.intent", "nas-services.json", ".nas-services.receipt"} {
			if err := stageNASEvidenceRole(context.Background(), root, role, []byte("owned synthetic bytes"), systemOps()); err != nil {
				t.Fatal(err)
			}
			if !consumeNASWriterEvents(watch, wd, role, false) {
				t.Fatal("actual publication events refused", role)
			}
		}
		if err := unix.Unlinkat(int(root.Fd()), ".nas-services.receipt", 0); err != nil {
			t.Fatal(err)
		}
		if !consumeNASWriterEvents(watch, wd, ".nas-services.receipt", true) {
			t.Fatal("actual retirement refused")
		}
	}
}

func TestNASWriterEventsRejectActualDriftAndMissingEvidence(t *testing.T) {
	for _, kind := range []string{"empty", "foreign-create", "watch-loss", "wrong-watch", "extra-after-stage", "invalid-role", "invalid-retirement"} {
		t.Run(kind, func(t *testing.T) {
			root, watch, wd := nasWriterEventFixture(t)
			role, retirement := "nas-services.json", false
			if kind == "watch-loss" {
				if _, err := unix.InotifyRmWatch(watch, uint32(wd)); err != nil {
					t.Fatal(err)
				}
			} else if kind != "empty" && kind != "foreign-create" {
				if err := stageNASEvidenceRole(context.Background(), root, role, []byte("synthetic"), systemOps()); err != nil {
					t.Fatal(err)
				}
			}
			switch kind {
			case "foreign-create", "extra-after-stage":
				if err := os.WriteFile(root.Name()+"/unexpected", []byte("evidence"), 0600); err != nil {
					t.Fatal(err)
				}
			case "wrong-watch":
				wd++
			case "invalid-role":
				role = "nas-evidence.json"
			case "invalid-retirement":
				retirement = true
			}
			if consumeNASWriterEvents(watch, wd, role, retirement) {
				t.Fatal("unexpected queue accepted", kind)
			}
		})
	}
}

func TestNASWriterEventsSplitRenameCoalescingAndMalformedRecords(t *testing.T) {
	const pending = ".nas-services.pending"
	valid := [][]byte{nasWriterEvent(unix.IN_CREATE, 0, pending), nasWriterEvent(unix.IN_MODIFY, 0, pending),
		nasWriterEvent(unix.IN_CLOSE_WRITE, 0, pending), nasWriterEvent(unix.IN_MOVED_FROM, 7, pending), nasWriterEvent(unix.IN_MOVED_TO, 7, "nas-services.json")}
	e := nasWriterEvents{descriptor: 1, role: "nas-services.json"}
	for i, record := range valid {
		if !e.consume(record) || e.complete() != (i == len(valid)-1) {
			t.Fatal("split rename or complete sequence refused", i)
		}
	}
	for _, replacement := range [][]byte{
		{0}, make([]byte, 16), valid[4][:17], nasWriterEvent(unix.IN_Q_OVERFLOW, 0, pending),
		nasWriterEvent(unix.IN_ATTRIB, 0, pending), nasWriterEvent(unix.IN_MOVED_TO, 8, "nas-services.json"),
		nasWriterEvent(unix.IN_MOVED_TO, 7, ".nas-services.base"), nasWriterEvent(unix.IN_MOVED_TO|unix.IN_ISDIR, 7, "nas-services.json"),
	} {
		e = nasWriterEvents{descriptor: 1, role: "nas-services.json"}
		for _, record := range valid[:4] {
			if !e.consume(record) {
				t.Fatal("valid prefix refused")
			}
		}
		if e.consume(replacement) {
			t.Fatal("malformed record accepted")
		}
	}
	e = nasWriterEvents{descriptor: 1, role: "nas-services.json"}
	for _, record := range [][]byte{valid[0], valid[1], valid[1], valid[2], valid[3], valid[4]} {
		if !e.consume(record) {
			t.Fatal("repeated modify refused")
		}
	}
	if !e.complete() || e.consume(valid[4]) {
		t.Fatal("incomplete or duplicate terminal sequence accepted")
	}
}

func TestNASWriterEventsRequireEachOrderedBoundary(t *testing.T) {
	const pending = ".nas-services.pending"
	sequence := [][]byte{nasWriterEvent(unix.IN_CREATE, 0, pending), nasWriterEvent(unix.IN_MODIFY, 0, pending),
		nasWriterEvent(unix.IN_CLOSE_WRITE, 0, pending), nasWriterEvent(unix.IN_MOVED_FROM, 7, pending), nasWriterEvent(unix.IN_MOVED_TO, 7, "nas-services.json")}
	for omit := range sequence {
		e := nasWriterEvents{descriptor: 1, role: "nas-services.json"}
		accepted := true
		for i, record := range sequence {
			if i != omit && !e.consume(record) {
				accepted = false
				break
			}
		}
		if accepted && e.complete() {
			t.Fatal("omitted boundary accepted", omit)
		}
	}
}

func TestNASWriterEventsRefuseBlockingWatchWithoutReading(t *testing.T) {
	root, watch, wd := nasWriterEventFixture(t)
	if err := unix.SetNonblock(watch, false); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(root.Name()+"/unexpected", []byte("retained evidence"), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := unix.IoctlGetInt(watch, unix.TIOCINQ)
	if err != nil || before <= 0 {
		t.Fatal("expected queued evidence", before, err)
	}
	if consumeNASWriterEvents(watch, wd, "nas-services.json", false) {
		t.Fatal("blocking watch accepted")
	}
	after, err := unix.IoctlGetInt(watch, unix.TIOCINQ)
	if err != nil || before != after {
		t.Fatal("blocking watch evidence consumed", before, after, err)
	}
}

func FuzzNASWriterEvents(f *testing.F) {
	f.Add(nasWriterEvent(unix.IN_CREATE, 0, ".nas-services.pending"))
	f.Add(nasWriterEvent(unix.IN_DELETE, 0, ".nas-services.receipt"))
	var complete []byte
	for _, record := range [][]byte{nasWriterEvent(unix.IN_CREATE, 0, ".nas-services.pending"), nasWriterEvent(unix.IN_MODIFY, 0, ".nas-services.pending"), nasWriterEvent(unix.IN_CLOSE_WRITE, 0, ".nas-services.pending"), nasWriterEvent(unix.IN_MOVED_FROM, 7, ".nas-services.pending"), nasWriterEvent(unix.IN_MOVED_TO, 7, ".nas-services.receipt")} {
		complete = append(complete, record...)
	}
	f.Add(complete)
	f.Add(make([]byte, 16))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 {
			return
		}
		before := bytes.Clone(data)
		for _, retirement := range []bool{false, true} {
			e := nasWriterEvents{descriptor: 1, role: ".nas-services.receipt", retirement: retirement}
			if e.consume(data) && e.complete() && e.consume(nasWriterEvent(unix.IN_CREATE, 0, ".nas-services.pending")) {
				t.Fatal("terminal sequence accepted an extra event")
			}
		}
		if !bytes.Equal(before, data) {
			t.Fatal("input mutated")
		}
	})
}
