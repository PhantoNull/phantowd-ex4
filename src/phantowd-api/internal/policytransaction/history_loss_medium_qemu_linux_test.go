//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policytransaction

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/configjson"
	"golang.org/x/sys/unix"
)

// This test-binary decoder binds a proof to the parent's closed medium choice.
// The legacy decoder and all normal constructors remain tmpfs-only.
func decodeHistoryLossGate(data []byte, stage, challenge string, pid int, medium disposableMedium) (crashGate, error) {
	parent, _, err := medium.location()
	if err != nil || len(data) == 0 || len(data) > 512 || data[len(data)-1] != '\n' || !knownCrashStage(stage) || !validChallenge(challenge) || pid <= 0 {
		return crashGate{}, ErrInvalid
	}
	if _, err := configjson.DecodeEnvelope(data, 512, 2, "stage", "challenge", "pid", "root"); err != nil {
		return crashGate{}, ErrInvalid
	}
	var g crashGate
	if json.Unmarshal(data, &g) != nil || g.Stage != stage || g.Challenge != challenge || g.PID != pid || len(g.Root) > 128 || filepath.Clean(g.Root) != g.Root || filepath.Dir(g.Root) != parent {
		return crashGate{}, ErrInvalid
	}
	const prefix = "phantowd-transaction-"
	base := filepath.Base(g.Root)
	if !strings.HasPrefix(base, prefix) || len(base) <= len(prefix) || len(base) > len(prefix)+32 {
		return crashGate{}, ErrInvalid
	}
	for _, ch := range base[len(prefix):] {
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9') {
			return crashGate{}, ErrInvalid
		}
	}
	return g, nil
}

func TestHistoryLossProofBindsClosedMedium(t *testing.T) {
	const challenge = "11111111222233334444555555555555"
	for _, medium := range []disposableMedium{disposableTmpfs, disposableFixedExt4} {
		parent, _, _ := medium.location()
		gate := crashGate{"receipt/directory-sync", challenge, 123, parent + "/phantowd-transaction-fixed"}
		wire, _ := json.Marshal(gate)
		wire = append(wire, '\n')
		if _, err := decodeHistoryLossGate(wire, gate.Stage, challenge, 123, medium); err != nil {
			t.Fatal("matching closed medium refused", err)
		}
		other := disposableTmpfs
		if medium == disposableTmpfs {
			other = disposableFixedExt4
		}
		for _, rejected := range []disposableMedium{other, disposableMedium(255)} {
			if _, err := decodeHistoryLossGate(wire, gate.Stage, challenge, 123, rejected); err != ErrInvalid {
				t.Fatal("foreign medium accepted")
			}
		}
		for _, bad := range [][]byte{nil, wire[:len(wire)-1], append(append([]byte(nil), wire...), wire...),
			[]byte(strings.Replace(string(wire), `"pid":123`, `"pid":124`, 1)),
			[]byte(strings.Replace(string(wire), `"pid":123`, `"pid":123,"pid":123`, 1)),
			[]byte(strings.Replace(string(wire), challenge, strings.Repeat("a", 32), 1)),
			[]byte(strings.Replace(string(wire), "receipt/directory-sync", "policy/directory-sync", 1)),
			[]byte(strings.Replace(string(wire), "phantowd-transaction-fixed", "phantowd-transaction-fixed/../other", 1)),
			[]byte(strings.Replace(string(wire), "phantowd-transaction-fixed", "phantowd-transaction-", 1)),
			[]byte(strings.Repeat("x", 513))} {
			if _, err := decodeHistoryLossGate(bad, gate.Stage, challenge, 123, medium); err != ErrInvalid {
				t.Fatal("malformed loss proof accepted")
			}
		}
		if medium == disposableFixedExt4 {
			if _, err := decodeCrashGate(wire, gate.Stage, challenge, 123); err != ErrInvalid {
				t.Fatal("legacy proof decoder widened")
			}
		}
	}
}

// Linux may refuse RO remount while an unlinked inode is still held even by
// an O_RDONLY descriptor. This negative control does not release writer or
// confirmed-history authority: it uses one unrelated known sibling fixture.
func TestHistoryExt4RemountRejectsUnlinkedReadPin(t *testing.T) {
	requireObserverMedia(t, false)
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal("orphan pin baseline")
	}
	path := filepath.Join(historyExt4Root, "history-orphan-read-witness")
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_EXCL|unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		t.Fatal("orphan readonly fixture open", err)
	}
	f := os.NewFile(uintptr(fd), "orphan-readonly-control")
	closed := false
	defer func() {
		if !closed {
			_ = f.Close()
		}
	}()
	if os.Remove(path) != nil {
		t.Fatal("orphan known-name unlink")
	}
	var st unix.Stat_t
	flags, err := unix.FcntlInt(f.Fd(), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY || unix.Fstat(fd, &st) != nil || st.Nlink != 0 {
		t.Fatal("orphan was not an unlinked readonly pin")
	}
	err = unix.Mount("", historyExt4Root, "", unix.MS_REMOUNT|unix.MS_RDONLY|observerMediaRestrictions, "")
	if err == nil {
		_ = unix.Mount("", historyExt4Root, "", unix.MS_REMOUNT|observerMediaRestrictions, "")
		t.Fatal("unlinked readonly pin unexpectedly admitted RO remount")
	}
	if !errors.Is(err, unix.EBUSY) {
		t.Fatal("orphan remount failure was not EBUSY", err)
	}
	requireObserverMedia(t, false)
	closed = true // Close is attempted once, never retried after uncertainty.
	if f.Close() != nil {
		t.Fatal("orphan pin close")
	}
	if err := unix.Mount("", historyExt4Root, "", unix.MS_REMOUNT|unix.MS_RDONLY|observerMediaRestrictions, ""); err != nil {
		t.Fatal("RO remount after verified orphan closure", err)
	}
	defer func() {
		if unix.Mount("", historyExt4Root, "", unix.MS_REMOUNT|observerMediaRestrictions, "") != nil {
			t.Error("orphan control mount restoration")
		}
	}()
	requireObserverMedia(t, true)
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(after) != len(before) {
		t.Fatal("orphan pin descriptor leak")
	}
}
