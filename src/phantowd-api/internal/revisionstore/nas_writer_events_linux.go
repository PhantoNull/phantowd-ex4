//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package revisionstore

import (
	"bytes"
	"encoding/binary"
	"errors"

	"golang.org/x/sys/unix"
)

// consumeNASWriterEvents is a bounded post-stage check for a future private
// coordinator's ORIGINAL nonblocking single-directory watch. Never use a standalone reader's
// watch or call this to clear review. A known event sequence is not attribution:
// the coordinator must also retain its root/flock, trust cooperating writers and
// verify the complete expected file identities/bytes before advancing its epoch.
// False is terminal uncertainty, not permission to drain again or retry effects.
func consumeNASWriterEvents(watch, descriptor int, role string, retirement bool) bool {
	if watch < 0 || descriptor < 1 || int(int32(descriptor)) != descriptor {
		return false
	}
	switch role {
	case ".nas-services.base", ".nas-services.intent", "nas-services.json", ".nas-services.receipt":
	default:
		return false
	}
	if retirement && role != ".nas-services.receipt" {
		return false
	}
	flags, err := unix.FcntlInt(uintptr(watch), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_NONBLOCK == 0 {
		return false
	}
	events := nasWriterEvents{descriptor: int32(descriptor), role: role, retirement: retirement}
	var buffer [4096]byte
	for range 4 {
		n, err := unix.Read(watch, buffer[:])
		if errors.Is(err, unix.EAGAIN) {
			return events.complete()
		}
		if err != nil || n <= 0 || !events.consume(buffer[:n]) {
			return false
		}
	}
	return false // Bound queued work; overflow or an unobserved tail never passes.
}

type nasWriterEvents struct {
	descriptor int32
	role       string
	retirement bool
	phase      int
	modified   bool
	cookie     uint32
}

func (e *nasWriterEvents) complete() bool {
	return (e.retirement && e.phase == 1) || (!e.retirement && e.phase == 4)
}

func (e *nasWriterEvents) consume(data []byte) bool {
	for len(data) > 0 {
		if len(data) < unix.SizeofInotifyEvent || int32(binary.NativeEndian.Uint32(data)) != e.descriptor {
			return false
		}
		mask, cookie, size := binary.NativeEndian.Uint32(data[4:]), binary.NativeEndian.Uint32(data[8:]), binary.NativeEndian.Uint32(data[12:])
		if size == 0 || size > 256 || uint64(size)+unix.SizeofInotifyEvent > uint64(len(data)) {
			return false
		}
		end := unix.SizeofInotifyEvent + int(size)
		if data[end-1] != 0 {
			return false
		}
		name := string(bytes.TrimRight(data[unix.SizeofInotifyEvent:end], "\x00"))
		data = data[end:]
		if e.complete() {
			return false
		}
		if e.retirement {
			if mask != unix.IN_DELETE || cookie != 0 || name != ".nas-services.receipt" {
				return false
			}
			e.phase = 1
			continue
		}
		switch e.phase {
		case 0:
			if mask != unix.IN_CREATE || cookie != 0 || name != ".nas-services.pending" {
				return false
			}
			e.phase = 1
		case 1:
			if name != ".nas-services.pending" || cookie != 0 || (mask != unix.IN_MODIFY && mask != unix.IN_CLOSE_WRITE) {
				return false
			}
			if mask == unix.IN_CLOSE_WRITE {
				if !e.modified {
					return false
				}
				e.phase = 2
			}
			e.modified = true // Identical unread MODIFY records may coalesce.
		case 2:
			if mask != unix.IN_MOVED_FROM || cookie == 0 || name != ".nas-services.pending" {
				return false
			}
			e.cookie, e.phase = cookie, 3
		case 3:
			if mask != unix.IN_MOVED_TO || cookie != e.cookie || name != e.role {
				return false
			}
			e.phase = 4
		}
	}
	return true
}
