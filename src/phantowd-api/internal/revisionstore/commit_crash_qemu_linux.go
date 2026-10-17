//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package revisionstore

import (
	"bytes"
	"os"
)

// QEMUCommitCrash is a sealed, constructor-bound fixture profile, not a backend
// or authority token. No non-QEMU build, HTTP caller or per-operation parameter
// can select it. Gate must block until the test parent sends actual SIGKILL.
type QEMUCommitCrash struct {
	revision uint64
	point    string
	gate     func()
	third    bool // separate sealed history profile; legacy constructor stays1/2
}

func NewQEMUCommitCrash(revision uint64, point string, gate func()) (QEMUCommitCrash, error) {
	if revision < 1 || revision > 2 || gate == nil {
		return QEMUCommitCrash{}, ErrUnsafe
	}
	switch point {
	case "partial-write", "full-write", "file-sync", "file-close", "before-rename", "after-rename", "directory-sync":
		return QEMUCommitCrash{revision: revision, point: point, gate: gate}, nil
	default:
		return QEMUCommitCrash{}, ErrUnsafe
	}
}

// NewQEMUThirdRevisionCrash selects ONLY revision3, for a second operation after
// independently confirmed revisions1/2. It does not widen the legacy1/2 factory
// or accept arbitrary target revisions from callers/HTTP.
func NewQEMUThirdRevisionCrash(point string, gate func()) (QEMUCommitCrash, error) {
	p, err := NewQEMUCommitCrash(2, point, gate)
	if err != nil {
		return QEMUCommitCrash{}, err
	}
	p.revision, p.third = 3, true
	return p, nil
}

// OpenAnchoredQEMUCrashWithCodec uses the SAME strict constructor, lock and real
// syscalls as OpenAnchoredWithCodec. Only one declared candidate revision can
// stop at one fixed success boundary. No caller FD is adopted, no result is
// fabricated, and an unexpectedly returning gate fails/poisons the Store rather
// than reporting success. Ordinary Store constructors are unchanged.
func OpenAnchoredQEMUCrashWithCodec[T any](parent *os.File, name string, codec Codec[T], profile QEMUCommitCrash) (*Store[T], error) {
	validRevision := profile.revision == 1 || profile.revision == 2
	if profile.third {
		validRevision = profile.revision == 3
	}
	if _, e := NewQEMUCommitCrash(1, profile.point, profile.gate); e != nil || !validRevision {
		return nil, e
	}
	s, e := OpenAnchoredWithCodec(parent, name, codec)
	if e != nil {
		return nil, e
	}
	original := s.io
	active, fired := false, false // serialized by the original Store mutex
	fire := func(point string) bool {
		if !active || fired || point != profile.point {
			return false
		}
		fired = true
		profile.gate()
		return true // test-gate return is NEVER successful publication
	}
	s.io.write = func(f *os.File, b []byte) (int, error) {
		candidate, e := codec.Decode(bytes.NewReader(b))
		if e != nil {
			return 0, ErrIO
		}
		active = codec.Revision(candidate) == profile.revision
		if active && profile.point == "partial-write" {
			if len(b) < 8 {
				return 0, ErrIO
			}
			n, e := original.write(f, b[:8])
			if e != nil || n != 8 {
				return n, ErrIO
			}
			fire("partial-write")
			return n, ErrIO
		}
		n, e := original.write(f, b)
		if e == nil && n == len(b) && fire("full-write") {
			return n, ErrIO
		}
		return n, e
	}
	s.io.sync = func(f *os.File) error {
		if e := original.sync(f); e != nil {
			return e
		}
		if fire("file-sync") {
			return ErrIO
		}
		return nil
	}
	s.io.close = func(f *os.File) error {
		if e := original.close(f); e != nil {
			return e
		}
		if fire("file-close") {
			return ErrIO
		}
		return nil
	}
	s.io.rename = func(a int, b string, c int, d string) error {
		if fire("before-rename") {
			return ErrIO
		}
		if e := original.rename(a, b, c, d); e != nil {
			return e
		}
		if fire("after-rename") {
			return ErrIO
		}
		return nil
	}
	s.io.syncDir = func(fd int) error {
		if e := original.syncDir(fd); e != nil {
			return e
		}
		if fire("directory-sync") {
			return ErrIO
		}
		return nil
	}
	return s, nil
}
