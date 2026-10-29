//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package revisionstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"maps"
	"os"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicyevidence"
	"golang.org/x/sys/unix"
)

type nasWriterBackend struct {
	io     fileOps
	random func([]byte) (int, error)
	remove func(int, string, int) error
}

func systemNASWriterBackend() nasWriterBackend {
	return nasWriterBackend{systemOps(), rand.Read, unix.Unlinkat}
}

// nasWriter owns a FRESH, never-exposed retention lifetime, not an existing
// diagnostic reader. Its original root/lock/watch and fixed backend never move.
// A trusted parent separately confirms exact base bytes and absence of consumers;
// matching records alone grant neither. No leases, RPC or product caller exist.
type nasWriter struct {
	self         *nasWriter
	retention    *BootstrapAuthority[naspolicy.Config]
	installation string
	backend      nasWriterBackend
	stamp        unix.Stat_t
	files        map[string]nasEvidenceFile
}

func openNASWriter(ctx context.Context, directory, installation string, confirmed []byte, backend nasWriterBackend) (*nasWriter, error) {
	if naspolicyevidence.Inspect(installation, confirmed, nil, nil, true) != naspolicyevidence.NoRecordedOperation ||
		backend.random == nil || backend.remove == nil || backend.io.write == nil || backend.io.sync == nil || backend.io.close == nil || backend.io.rename == nil || backend.io.syncDir == nil {
		return nil, ErrInvalid
	}
	r, err := OpenBootstrapAuthorityWithCodec(ctx, directory, nasEvidenceCodec())
	if r == nil {
		return nil, err
	}
	w := &nasWriter{retention: r, installation: installation, backend: backend, stamp: r.initial}
	w.self = w
	if err != nil {
		return w, err // Preserve originals after uncertain constructor cleanup.
	}
	kind, err := w.refresh(ctx, nil, "")
	if err == nil && bytes.Equal(w.files["nas-services.json"].data, confirmed) &&
		((kind == naspolicyevidence.NoRecordedOperation && len(w.files) == 2) || (kind == naspolicyevidence.MatchingLocalRecords && len(w.files) == 5)) {
		return w, nil
	}
	r.review = true
	if w.Close() != nil {
		return w, ErrReview
	}
	return nil, ErrReview
}

// refresh uses a fresh confined cursor, never a new root/lock/watch. Only the
// explicitly changed role may have new metadata; all other bytes AND stamps
// remain exact. The registered watch must be quiet across the complete census.
func (w *nasWriter) refresh(ctx context.Context, expected map[string]nasEvidenceFile, changed string) (naspolicyevidence.Kind, error) {
	r := w.retention
	fd := int(r.root.Fd())
	var before, after unix.Stat_t
	if ctx.Err() != nil || unix.Fstat(fd, &before) != nil || before.Dev != r.initial.Dev || before.Ino != r.initial.Ino ||
		before.Mode != r.initial.Mode || before.Uid != r.initial.Uid || before.Gid != r.initial.Gid || before.Nlink != r.initial.Nlink ||
		(changed == "" && policyStamp(before) != policyStamp(w.stamp)) || !r.quietLocked() {
		return naspolicyevidence.Unavailable, ErrReview
	}
	cursorFD, err := unix.Openat2(fd, ".", &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOATIME | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_XDEV | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return naspolicyevidence.Unavailable, ErrReview
	}
	cursor := os.NewFile(uintptr(cursorFD), "nas-writer-confined-cursor")
	if unix.Fstat(cursorFD, &after) != nil || policyStamp(after) != policyStamp(before) {
		cursor.Close()
		return naspolicyevidence.Unavailable, ErrReview
	}
	got := make(map[string]nasEvidenceFile)
	kind, readErr := collectNASEvidenceSet(ctx, cursor, before, w.installation, got)
	closeErr := cursor.Close()
	if readErr != nil || closeErr != nil || kind.Pending || unix.Fstat(fd, &after) != nil || policyStamp(before) != policyStamp(after) || !r.quietLocked() || ctx.Err() != nil {
		return naspolicyevidence.Unavailable, ErrReview
	}
	if expected != nil {
		if len(got) != len(expected) {
			return naspolicyevidence.Unavailable, ErrReview
		}
		for name, file := range got {
			old, exists := expected[name]
			if !exists || !bytes.Equal(file.data, old.data) || (name != changed && policyStamp(file.stat) != policyStamp(old.stat)) {
				return naspolicyevidence.Unavailable, ErrReview
			}
		}
	}
	w.files, w.stamp = got, after
	return kind.Kind, nil
}

func (w *nasWriter) Commit(ctx context.Context, base, next []byte) (result error) {
	if w == nil || w.self != w || ctx == nil || len(base) == 0 || len(next) == 0 || len(base) > naspolicy.MaxInputBytes || len(next) > naspolicy.MaxInputBytes {
		return ErrInvalid
	}
	r := w.retention
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.review || r.closeFailed {
		return ErrReview
	}
	if r.closed {
		return ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := w.refresh(ctx, w.files, ""); err != nil {
		r.review = true
		return ErrReview
	}
	base, next = bytes.Clone(base), bytes.Clone(next)
	if !bytes.Equal(base, w.files["nas-services.json"].data) {
		return ErrConflict
	}
	var id [16]byte
	n, err := w.backend.random(id[:])
	if err != nil || n != len(id) {
		return ErrIO
	}
	var prior struct {
		Operation string `json:"operation_id"`
	}
	if old, exists := w.files[".nas-services.intent"]; exists && json.Unmarshal(old.data, &prior) != nil {
		r.review = true
		return ErrReview
	}
	operation := hex.EncodeToString(id[:])
	if operation == prior.Operation {
		return ErrConflict
	}
	intent, receipt, err := naspolicyevidence.EncodeOperation(w.installation, operation, base, next)
	if err != nil {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	defer func() {
		if result != nil {
			r.review, result = true, ErrReview // Never retry, clear a watch or clean pending.
		}
	}()
	for _, step := range []struct {
		role string
		data []byte
	}{{".nas-services.base", base}, {".nas-services.intent", intent}, {"nas-services.json", next}, {".nas-services.receipt", receipt}} {
		if _, err := w.refresh(ctx, w.files, ""); err != nil {
			return ErrReview
		}
		if step.role == "nas-services.json" {
			if old, exists := w.files[".nas-services.receipt"]; exists {
				got, err := readNASEvidenceRole(ctx, int(r.root.Fd()), ".nas-services.receipt", naspolicyevidence.MaxRecordBytes, old.stat)
				if err != nil || !bytes.Equal(got, old.data) || ctx.Err() != nil || w.backend.remove(int(r.root.Fd()), ".nas-services.receipt", 0) != nil ||
					ctx.Err() != nil || w.backend.io.syncDir(int(r.root.Fd())) != nil || !consumeNASWriterEvents(r.watch, r.descriptor, ".nas-services.receipt", true) {
					return ErrReview
				}
				expected := maps.Clone(w.files)
				delete(expected, ".nas-services.receipt")
				if _, err := w.refresh(ctx, expected, ".nas-services.receipt"); err != nil {
					return ErrReview
				}
			}
		}
		if stageNASEvidenceRole(ctx, r.root, step.role, step.data, w.backend.io) != nil || !consumeNASWriterEvents(r.watch, r.descriptor, step.role, false) {
			return ErrReview
		}
		expected := maps.Clone(w.files)
		expected[step.role] = nasEvidenceFile{data: step.data}
		kind, err := w.refresh(ctx, expected, step.role)
		if err != nil || (step.role == ".nas-services.receipt" && kind != naspolicyevidence.MatchingLocalRecords) {
			return ErrReview
		}
	}
	return nil
}

func (w *nasWriter) Close() error {
	if w == nil || w.self != w {
		return ErrInvalid
	}
	return w.retention.Close()
}

func (*nasWriter) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
func (*nasWriter) UnmarshalJSON([]byte) error   { return ErrInvalid }
