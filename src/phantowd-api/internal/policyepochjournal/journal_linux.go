//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policyepochjournal

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/policyevidence"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/revisionstore"
)

// Journal holds the fixed child's original Store/flock. Parent is borrowed and
// must outlive it; trusted ancestors/medium and cooperating writers are required.
// No consumer lease is issued. Copies are invalid; no operation accepts a path,
// role, ID, codec or backend. This is NOT the complete product state-root Owner.
type Journal struct{ state *journalState }

type journalState struct {
	mu                          sync.Mutex
	self                        *Journal
	store                       *revisionstore.Store[document]
	installation                string
	sequence                    uint64
	doc                         document
	review, closed, closeFailed bool
	commit                      func(uint64, document) error
	load                        func() (document, []byte, error)
	closeStore                  func() error
}

func codec() revisionstore.Codec[document] {
	return revisionstore.Codec[document]{CurrentName: "epoch.json", PendingName: ".epoch.pending", MaxBytes: maxDocumentBytes,
		Decode: decodeDocument, Validate: document.validate, Revision: func(d document) uint64 { return d.Revision }}
}

// OpenFresh requires a separately provisioned EMPTY policy-session child. It
// neither creates directories nor adopts existing records, pending or unknown
// entries. It never initializes/syncs/deletes during opening. Non-nil WITH error
// means retained close uncertainty, not usable admission. Sequence is trusted
// constructor data, not proof of successor allocation or antirollback.
func OpenFresh(ctx context.Context, parent *os.File, installation string, sequence uint64) (*Journal, error) {
	if ctx == nil || parent == nil || sequence == 0 {
		return nil, ErrInvalid
	}
	absent := policyevidence.Slot{State: policyevidence.Absent}
	if _, err := policyevidence.Match(policyevidence.Evidence{InstallationID: installation, Intent: absent, Receipt: absent, Current: absent}); err != nil {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s, err := revisionstore.OpenAnchoredWithCodec(parent, "policy-session", codec())
	if err != nil {
		if errors.Is(err, revisionstore.ErrBusy) {
			return nil, ErrBusy
		}
		return nil, ErrReview
	}
	j := &Journal{state: &journalState{store: s, installation: installation, sequence: sequence, commit: s.Commit, load: s.LoadExact, closeStore: s.Close}}
	j.state.self = j
	_, wire, loadErr := j.state.load()
	clear(wire)
	if loadErr != revisionstore.ErrNotInitialized || ctx.Err() != nil {
		reason := error(ErrReview)
		if loadErr == nil {
			reason = ErrExisting
		}
		if ctx.Err() != nil {
			reason = ctx.Err()
		}
		if j.Close() != nil {
			return j, errors.Join(ErrReview, reason)
		}
		return nil, reason
	}
	return j, nil
}
func (j *Journal) valid() bool {
	return j != nil && j.state != nil && j.state.self == j && j.state.store != nil && j.state.commit != nil && j.state.load != nil && j.state.closeStore != nil
}
func (j *Journal) ready(ctx context.Context) error {
	if j.state.review || j.state.closeFailed {
		return ErrReview
	}
	if j.state.closed {
		return ErrClosed
	}
	return ctx.Err()
}
func (j *Journal) poison(ctx context.Context) error {
	j.state.review = true
	return errors.Join(ErrReview, ctx.Err())
}
func (j *Journal) verify(ctx context.Context) error {
	d, wire, err := j.state.load()
	defer clear(wire)
	if j.state.doc.Revision == 0 {
		if err != revisionstore.ErrNotInitialized {
			return j.poison(ctx)
		}
	} else if err != nil || d != j.state.doc || !sameWire(j.state.doc, wire) {
		return j.poison(ctx)
	}
	if ctx.Err() != nil {
		return j.poison(ctx)
	}
	return nil
}
func (j *Journal) publish(ctx context.Context, next document) error {
	if next.validate() != nil {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := j.verify(ctx); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if j.state.commit(j.state.doc.Revision, next) != nil {
		return j.poison(ctx)
	}
	d, wire, err := j.state.load()
	defer clear(wire)
	if err != nil || d != next || !sameWire(next, wire) || ctx.Err() != nil {
		return j.poison(ctx)
	}
	j.state.doc = next
	return nil
}

func (j *Journal) RecordOpening(ctx context.Context, policy []byte) error {
	if !j.valid() || ctx == nil {
		return ErrInvalid
	}
	j.state.mu.Lock()
	defer j.state.mu.Unlock()
	if err := j.ready(ctx); err != nil {
		return err
	}
	if j.state.doc.Revision != 0 {
		return ErrConflict
	}
	absent := policyevidence.Slot{State: policyevidence.Absent}
	if _, err := policyevidence.MatchEpoch(j.state.installation, absent, absent, policyevidence.Slot{State: policyevidence.Present, Data: policy}); err != nil {
		return ErrInvalid
	}
	var id [16]byte
	if n, err := rand.Read(id[:]); err != nil || n != len(id) {
		clear(id[:])
		return ErrInvalid
	}
	opening, err := policyevidence.DeclareEpochOpening(j.state.installation, hex.EncodeToString(id[:]), j.state.sequence, policy)
	clear(id[:])
	if err != nil {
		return ErrInvalid
	}
	wire, err := policyevidence.EncodeEpochOpening(opening)
	defer clear(wire)
	if err != nil {
		return ErrInvalid
	}
	return j.publish(ctx, openingDocument(j.state.installation, wire))
}

// Records a DECLARATION, not successful consumer drain/Close or boot permission.
// A future retained product coordinator must establish those preconditions.
func (j *Journal) RecordClosure(ctx context.Context, policy []byte) error {
	if !j.valid() || ctx == nil {
		return ErrInvalid
	}
	j.state.mu.Lock()
	defer j.state.mu.Unlock()
	if err := j.ready(ctx); err != nil {
		return err
	}
	if j.state.doc.Revision != 1 {
		return ErrConflict
	}
	opening, err := recordBytes(j.state.doc.Opening, false)
	defer clear(opening)
	if err != nil {
		return j.poison(ctx)
	}
	closure, err := policyevidence.DeclareEpochClosure(opening, policy)
	if err != nil {
		return ErrInvalid
	}
	wire, err := policyevidence.EncodeEpochClosure(closure)
	defer clear(wire)
	if err != nil {
		return ErrInvalid
	}
	next := j.state.doc
	next.Revision = 2
	next.Closure = base64.StdEncoding.EncodeToString(wire)
	return j.publish(ctx, next)
}

// Observe compares only supplied policy DATA with this journal's declarations.
// No path or current-policy origin, history completeness or admission is proved.
func (j *Journal) Observe(ctx context.Context, policy []byte) (policyevidence.EpochDiagnosis, error) {
	if !j.valid() || ctx == nil {
		return policyevidence.EpochDiagnosis{}, ErrInvalid
	}
	j.state.mu.Lock()
	defer j.state.mu.Unlock()
	if err := j.ready(ctx); err != nil {
		return policyevidence.EpochDiagnosis{}, err
	}
	if err := j.verify(ctx); err != nil {
		return policyevidence.EpochDiagnosis{}, err
	}
	current := policyevidence.Slot{State: policyevidence.Present, Data: policy}
	var d policyevidence.EpochDiagnosis
	var err error
	if j.state.doc.Revision == 0 {
		absent := policyevidence.Slot{State: policyevidence.Absent}
		d, err = policyevidence.MatchEpoch(j.state.installation, absent, absent, current)
	} else {
		d, err = j.state.doc.observe(current)
	}
	if err != nil {
		return policyevidence.EpochDiagnosis{}, ErrInvalid
	}
	if ctx.Err() != nil {
		return policyevidence.EpochDiagnosis{}, j.poison(ctx)
	}
	return d, nil
}

// Close only releases references. It NEVER writes a closure declaration or
// deletes evidence, even after review. An uncertain close is terminal, no retry.
func (j *Journal) Close() error {
	if !j.valid() {
		return ErrInvalid
	}
	j.state.mu.Lock()
	defer j.state.mu.Unlock()
	if j.state.closeFailed {
		return ErrReview
	}
	if j.state.closed {
		return nil
	}
	if j.state.closeStore() != nil {
		j.state.closeFailed = true
		j.state.review = true
		return ErrReview
	}
	j.state.closed = true
	j.state.doc = document{}
	return nil
}
func (Journal) MarshalJSON() ([]byte, error) { return nil, ErrPrivate }
func (*Journal) UnmarshalJSON([]byte) error  { return ErrPrivate }
func (Journal) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "policy-session-journal{private}")
}
