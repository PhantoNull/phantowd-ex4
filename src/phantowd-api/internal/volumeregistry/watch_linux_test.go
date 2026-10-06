// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package volumeregistry

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func registryEvent(wd int32, mask uint32, name []byte) []byte {
	data := make([]byte, unix.SizeofInotifyEvent+len(name))
	binary.NativeEndian.PutUint32(data[:4], uint32(wd))
	binary.NativeEndian.PutUint32(data[4:8], mask)
	binary.NativeEndian.PutUint32(data[12:16], uint32(len(name)))
	copy(data[16:], name)
	return data
}

func TestRegistryChangeRecordsAreBoundedAndFailClosed(t *testing.T) {
	for _, mask := range []uint32{unix.IN_MODIFY, unix.IN_ATTRIB, unix.IN_CLOSE_WRITE, unix.IN_CREATE, unix.IN_DELETE, unix.IN_MOVED_FROM, unix.IN_MOVED_TO, unix.IN_CREATE | unix.IN_ISDIR} {
		data := registryEvent(1, mask, []byte("fixture\x00"))
		if changed, err := consumeChanges(append(data, data...), 1); err != nil || !changed {
			t.Fatal("valid mutation refused", mask, err)
		}
	}
	for _, data := range [][]byte{
		{1}, registryEvent(2, unix.IN_MODIFY, nil), registryEvent(-1, unix.IN_Q_OVERFLOW, nil),
		registryEvent(1, unix.IN_IGNORED, nil), registryEvent(1, unix.IN_UNMOUNT, nil), registryEvent(1, unix.IN_MOVE_SELF, nil), registryEvent(1, unix.IN_DELETE_SELF, nil),
		registryEvent(1, unix.IN_ACCESS, nil), registryEvent(1, 0, nil),
		append(registryEvent(1, unix.IN_MODIFY, nil), 1),
	} {
		if changed, err := consumeChanges(data, 1); err != ErrObservation || changed {
			t.Fatal("invalid/lost event produced partial observation")
		}
	}
	tooLong := registryEvent(1, unix.IN_MODIFY, nil)
	binary.NativeEndian.PutUint32(tooLong[12:16], ^uint32(0))
	if _, err := consumeChanges(tooLong, 1); err != ErrObservation {
		t.Fatal("overflow length accepted")
	}
}

func TestRegistryWatchDescriptorFlagsLossAndClose(t *testing.T) {
	_, borrowed := readerFixture(t)
	r, err := Open(borrowed)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	s, err := r.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	flags, err := unix.FcntlInt(uintptr(r.watchFD), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatal("watch descriptor can escape exec", err)
	}
	flags, err = unix.FcntlInt(uintptr(r.watchFD), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_NONBLOCK == 0 {
		t.Fatal("watch drain can block", err)
	}
	if _, err := unix.InotifyRmWatch(r.watchFD, uint32(r.watchID)); err != nil {
		t.Fatal(err)
	}
	if r.Recheck(context.Background(), s) != ErrObservation || !r.watchBroken {
		t.Fatal("watch loss accepted")
	}
	if _, err := r.Read(context.Background()); err != ErrObservation {
		t.Fatal("lost watch silently reopened/downgraded")
	}
	fd := r.watchFD
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != unix.EBADF {
		t.Fatal("closed reader retained watch descriptor", err)
	}
}

func TestRegistryWatchDrainBudgetAndGenerationOverflow(t *testing.T) {
	// Test-only finite event source; runtime always uses its fixed inotify FD.
	file, err := os.CreateTemp(t.TempDir(), "events")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	event := registryEvent(1, unix.IN_MODIFY, nil)
	for written := 0; written < maxEventBytes; written += len(event) {
		if _, err := file.Write(event); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := file.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	r := &Reader{watchFD: int(file.Fd()), watchID: 1}
	if r.drainChangesLocked() != ErrObservation || !r.watchBroken {
		t.Fatal("unbounded event source accepted")
	}
	position, err := file.Seek(0, 1)
	if err != nil || position != maxEventBytes {
		t.Fatal("event drain exceeded budget", position, err)
	}
	if _, err := file.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	if r.drainChangesLocked() != ErrObservation {
		t.Fatal("broken watch retried")
	}
	if position, err := file.Seek(0, 1); err != nil || position != 0 {
		t.Fatal("broken watch performed more reads", position, err)
	}
	dir, borrowed := readerFixture(t)
	real, err := Open(borrowed)
	if err != nil {
		t.Fatal(err)
	}
	defer real.Close()
	real.generation = ^uint64(0)
	prior, err := real.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, currentName), 0644); err != nil {
		t.Fatal(err)
	}
	if real.Recheck(context.Background(), prior) != ErrObservation || !real.watchBroken {
		t.Fatal("generation overflow wrapped")
	}
}

func TestRegistryInvalidPriorDoesNotConsumeQueuedChanges(t *testing.T) {
	dir, borrowed := readerFixture(t)
	r, err := Open(borrowed)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	prior, err := r.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, currentName), 0644); err != nil {
		t.Fatal(err)
	}
	if r.Recheck(context.Background(), Snapshot{}) != ErrObservation || r.generation != prior.generation {
		t.Fatal("invalid prior consumed kernel events")
	}
	if r.Recheck(context.Background(), prior) != ErrObservation || r.generation == prior.generation {
		t.Fatal("valid prior did not observe queued mutation")
	}
}
