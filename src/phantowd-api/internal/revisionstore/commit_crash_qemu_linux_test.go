//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package revisionstore

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestQEMUCommitCrashProfileRequiresClosedValidConstruction(t *testing.T) {
	for _, revision := range []uint64{0, 3} {
		if _, e := NewQEMUCommitCrash(revision, "file-sync", func() {}); e != ErrUnsafe {
			t.Fatal("invalid target")
		}
	}
	if _, e := NewQEMUCommitCrash(1, "unknown", func() {}); e != ErrUnsafe {
		t.Fatal("unknown point")
	}
	if _, e := NewQEMUCommitCrash(1, "file-sync", nil); e != ErrUnsafe {
		t.Fatal("nil gate")
	}
	if s, e := OpenAnchoredQEMUCrashWithCodec(nil, "policy", shareCodec(), QEMUCommitCrash{}); s != nil || e != ErrUnsafe {
		t.Fatal("zero profile admitted")
	}
}
func TestQEMUCommitCrashProfileBindsRevisionAndActualBoundary(t *testing.T) {
	for _, point := range []string{"partial-write", "full-write", "file-sync", "file-close", "before-rename", "after-rename", "directory-sync"} {
		t.Run(point, func(t *testing.T) {
			parent, dir := anchoredFixture(t)
			calls := 0
			profile, e := NewQEMUCommitCrash(2, point, func() { calls++ })
			if e != nil {
				t.Fatal(e)
			}
			s, e := OpenAnchoredQEMUCrashWithCodec(parent, "policy", shareCodec(), profile)
			if e != nil {
				t.Fatal(e)
			}
			defer s.Close()
			if s.Commit(0, policy(1)) != nil || calls != 0 {
				t.Fatal("profile intercepted confirmed base")
			}
			if s.Commit(1, policy(2)) == nil || calls != 1 {
				t.Fatal("returning gate reported success or missed boundary")
			}
			if e := s.Commit(1, policy(2)); e != ErrUncertain || calls != 1 {
				t.Fatal("gate failure admitted retry")
			}
			want, _ := json.Marshal(policy(1))
			next, _ := json.Marshal(policy(2))
			published := point == "after-rename" || point == "directory-sync"
			if published {
				want = next
			}
			actual, e := os.ReadFile(filepath.Join(dir, currentName))
			if e != nil || !bytes.Equal(actual, want) {
				t.Fatal("wrong actual current boundary")
			}
			pending, e := os.ReadFile(filepath.Join(dir, pendingName))
			if published {
				if !os.IsNotExist(e) {
					t.Fatal("published pending survived")
				}
			} else {
				if point == "partial-write" {
					next = next[:8]
				}
				if e != nil || !bytes.Equal(pending, next) {
					t.Fatal("wrong actual pending bytes")
				}
			}
		})
	}
}
