// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package volumeregistry

import (
	"encoding/binary"
	"errors"
	"strconv"

	"golang.org/x/sys/unix"
)

const mutationEvents = unix.IN_MODIFY | unix.IN_ATTRIB | unix.IN_CLOSE_WRITE | unix.IN_CREATE | unix.IN_DELETE | unix.IN_MOVED_FROM | unix.IN_MOVED_TO
const lostWatchEvents = unix.IN_DELETE_SELF | unix.IN_MOVE_SELF | unix.IN_UNMOUNT | unix.IN_IGNORED | unix.IN_Q_OVERFLOW
const maxEventBytes = 64 << 10

func (r *Reader) openWatchLocked() error {
	var proc unix.Statfs_t
	if unix.Statfs("/proc/self/fd", &proc) != nil || proc.Type != unix.PROC_SUPER_MAGIC {
		return ErrObservation
	}
	fd, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		return ErrObservation
	}
	// Fixed process-owned descriptor anchor, not caller-supplied path traversal.
	wd, err := unix.InotifyAddWatch(fd, "/proc/self/fd/"+strconv.Itoa(r.dir), mutationEvents|lostWatchEvents|unix.IN_ONLYDIR)
	if err != nil || wd < 0 {
		unix.Close(fd)
		return ErrObservation
	}
	r.watchFD, r.watchID = fd, wd
	return nil
}

// No goroutine/background polling, retries or unbounded event accumulation in
// userspace. Queue overflow/watch uncertainty is sticky until explicit close.
func (r *Reader) drainChangesLocked() error {
	if r.watchBroken || r.watchFD < 0 {
		return ErrObservation
	}
	var buffer [4096]byte
	consumed, changed := 0, false
	for consumed < maxEventBytes {
		n, err := unix.Read(r.watchFD, buffer[:])
		if errors.Is(err, unix.EAGAIN) {
			if changed {
				if r.generation == ^uint64(0) {
					break
				}
				r.generation++
			}
			return nil
		}
		if err != nil || n <= 0 {
			break
		}
		consumed += n
		mutation, err := consumeChanges(buffer[:n], r.watchID)
		if err != nil {
			break
		}
		changed = changed || mutation
	}
	r.watchBroken = true
	return ErrObservation
}

// Inotify records use native-endian fixed headers followed by a bounded name.
// Names/cookies are never retained, logged, serialized or used to select files.
func consumeChanges(data []byte, watchID int) (bool, error) {
	changed := false
	for len(data) != 0 {
		if len(data) < unix.SizeofInotifyEvent {
			return false, ErrObservation
		}
		wd := int32(binary.NativeEndian.Uint32(data[:4]))
		mask := binary.NativeEndian.Uint32(data[4:8])
		length := binary.NativeEndian.Uint32(data[12:16])
		if wd != int32(watchID) || mask&lostWatchEvents != 0 ||
			mask&mutationEvents == 0 || mask&^(uint32(mutationEvents)|uint32(unix.IN_ISDIR)) != 0 ||
			length > uint32(len(data)-unix.SizeofInotifyEvent) {
			return false, ErrObservation
		}
		changed = true
		data = data[unix.SizeofInotifyEvent+int(length):]
	}
	return changed, nil
}
