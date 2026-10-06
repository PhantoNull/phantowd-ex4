//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package iscsicredentials retains recoverable CHAP material for an internal,
// fixed trusted consumer. It exposes no HTTP, provisioning or rotation writer.
package iscsicredentials

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"sync"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/configjson"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsipolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/revisionstore"
)

var (
	ErrInvalid     = errors.New("invalid CHAP credential selection")
	ErrUnavailable = errors.New("CHAP credentials unavailable")
	ErrReview      = errors.New("CHAP credentials require review")
	ErrBusy        = errors.New("CHAP credentials retained by a consumer")
	ErrClosed      = errors.New("CHAP credential claim closed")
)

const maxBytes = 256 << 10
const maxEntries = iscsipolicy.MaxTargets * iscsipolicy.MaxInitiators * 2

// Unlike web-login verifiers, this private disk document deliberately contains
// recoverable plaintext. JSON encoding is only for the protected local store.
// Text formatting is always redacted, including private nested fields.
type document struct {
	redacted
	Kind          string  `json:"format"`
	SchemaVersion int     `json:"schema_version"`
	Revision      uint64  `json:"revision"`
	Entries       []entry `json:"entries"`
}
type entry struct {
	redacted
	Ref    iscsipolicy.SecretRef `json:"ref"`
	Secret string                `json:"secret"`
}
type redacted struct{}

func (redacted) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, "[redacted CHAP material]") }

// Opaque values refuse JSON for both pointers and mistakenly copied values;
// the promoted empty-marker methods never copy an owner's mutex.
type opaque struct{ redacted }

func (opaque) MarshalJSON() ([]byte, error) { return nil, ErrUnavailable }
func (*opaque) UnmarshalJSON([]byte) error  { return ErrUnavailable }

func validRef(ref iscsipolicy.SecretRef) bool {
	s := string(ref)
	if len(s) == 0 || len(s) > 64 || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// Backend eligibility, NOT an entropy measurement or a protocol-wide rule.
// Printable 16..128-octet tokens avoid configfs terminators/whitespace and LIO's
// reserved NULL prefix. Generation/import provenance remains an activation gate.
func validSecret(s string) bool {
	if len(s) < 16 || len(s) > 128 || strings.HasPrefix(s, "NULL") {
		return false
	}
	for _, c := range s {
		if c < 33 || c > 126 {
			return false
		}
	}
	return true
}
func validate(d document) error {
	if d.Kind != "phantowd-chap-credentials" || d.SchemaVersion != 1 || d.Revision == 0 ||
		d.Entries == nil || len(d.Entries) > maxEntries {
		return ErrInvalid
	}
	refs, values := map[iscsipolicy.SecretRef]bool{}, map[string]bool{}
	for _, e := range d.Entries {
		if !validRef(e.Ref) || refs[e.Ref] || !validSecret(e.Secret) || values[e.Secret] {
			return ErrInvalid
		}
		refs[e.Ref], values[e.Secret] = true, true
	}
	return nil
}
func decode(r io.Reader) (document, error) {
	var d document
	if r == nil || configjson.Decode(r, &d, maxBytes, 5, map[string]bool{
		"format": true, "schema_version": true, "revision": true, "entries": true, "ref": true, "secret": true,
	}) != nil || validate(d) != nil {
		return document{}, ErrInvalid
	}
	return d, nil
}
func codec() revisionstore.Codec[document] {
	return revisionstore.Codec[document]{CurrentName: "chap-secrets.json", PendingName: ".chap-secrets.pending", MaxBytes: maxBytes,
		Decode: decode, Validate: validate, Revision: func(d document) uint64 { return d.Revision }}
}

type Owner struct {
	opaque
	self  *Owner
	store *revisionstore.OwnedStore[document]
}

// Open requires stable effective UID 0 and a pre-provisioned local root-owned
// 0700 directory under trusted parents, with a root-owned 0600 single-link file.
// The shared transaction engine performs its reopen fsync boundary, but this
// wrapper cannot create, initialize, commit, recover or rotate a document.
func Open(directory string) (*Owner, error) {
	if os.Geteuid() != 0 {
		return nil, ErrUnavailable
	}
	s, err := revisionstore.OpenOwnedWithCodec(directory, codec())
	if err != nil {
		return nil, mapError(err)
	}
	o := &Owner{store: s}
	o.self = o
	return o, nil
}
func mapError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, revisionstore.ErrReview):
		return ErrReview
	case errors.Is(err, revisionstore.ErrBusy):
		return ErrBusy
	case errors.Is(err, revisionstore.ErrClosed):
		return ErrClosed
	default:
		return ErrUnavailable
	}
}
func (o *Owner) Close() error {
	if o == nil || o.self != o || o.store == nil {
		return ErrInvalid
	}
	return mapError(o.store.Close())
}

// Consumer is fixed trusted in-process backend code captured at acquisition,
// never an HTTP option or a per-operation injection. Prepare may partially
// acquire resources on error. The containing lifecycle MUST stop/join all of
// its borrowers, including kernel credentials, before releasing a Bundle.
type Consumer interface {
	PrepareCredentials(context.Context, []Credential) error
}

type Credential struct {
	opaque
	InitiatorName string
	Mode          string
	InitiatorUser string
	Incoming      Secret
	TargetUser    string
	Outgoing      Secret
}

// Secret is an opaque borrowed buffer, not a string/JSON/byte-return API. Copies
// share the same lifetime. Only the fixed trusted consumer may write it to its
// credential sink; that consumer must never log or independently retain copies.
type Secret struct {
	opaque
	buffer *secretBuffer
}
type secretBuffer struct {
	opaque
	mu       sync.Mutex
	value    []byte
	released bool
}

func (s Secret) WriteTo(w io.Writer) (int64, error) {
	if s.buffer == nil || w == nil {
		return 0, ErrUnavailable
	}
	s.buffer.mu.Lock()
	defer s.buffer.mu.Unlock()
	if s.buffer.released {
		return 0, ErrClosed
	}
	n, err := w.Write(s.buffer.value)
	if err != nil || n != len(s.buffer.value) {
		return 0, ErrUnavailable
	}
	return int64(n), nil
}
func (s Secret) wipe() {
	if s.buffer == nil {
		return
	}
	s.buffer.mu.Lock()
	defer s.buffer.mu.Unlock()
	clear(s.buffer.value)
	s.buffer.released = true
}
func newSecret(value string) Secret { return Secret{buffer: &secretBuffer{value: []byte(value)}} }

type Bundle struct {
	opaque
	self                       *Bundle
	mu                         sync.Mutex
	claim                      *revisionstore.PolicyLease[document]
	consumer                   Consumer
	peers                      []Credential
	prepared, released, review bool
}

// Acquire resolves EVERY reference in the validated policy before selecting
// one target; no partial/foreign/missing material is returned. All disk values
// are distinct (including unused entries), so different symbolic refs cannot
// conceal cross-peer/direction reuse. The containing owner retains its OWN
// coherent policy lease too; this snapshot alone grants no activation authority.
func (o *Owner) Acquire(ctx context.Context, expected uint64, policy naspolicy.Config, targetID iscsipolicy.TargetID, consumer Consumer) (_ *Bundle, result error) {
	if o == nil || o.self != o || o.store == nil || ctx == nil || os.Geteuid() != 0 || policy.Validate() != nil || targetID == "" || nilConsumer(consumer) {
		return nil, ErrInvalid
	}
	claim, err := o.store.Acquire(ctx, expected)
	if err != nil {
		return nil, mapError(err)
	}
	keep := false
	defer func() {
		if !keep && claim.Release() != nil {
			result = ErrReview
		}
	}()
	d, err := claim.Snapshot(ctx)
	if err != nil {
		return nil, mapError(err)
	}
	values := make(map[iscsipolicy.SecretRef]string, len(d.Entries))
	for _, e := range d.Entries {
		values[e.Ref] = e.Secret
	}
	var selected *iscsipolicy.Target
	for i := range policy.ISCSI.Targets {
		target := &policy.ISCSI.Targets[i]
		for _, peer := range target.Initiators {
			a := peer.Authentication
			if strings.HasPrefix(a.InitiatorUser, "NULL") || values[a.InitiatorSecretRef] == "" ||
				a.Mode == "mutual-chap" && (strings.HasPrefix(a.TargetUser, "NULL") || values[a.TargetSecretRef] == "") {
				return nil, ErrInvalid
			}
		}
		if target.ID == targetID {
			selected = target
		}
	}
	if selected == nil || claim.Verify(ctx) != nil {
		return nil, ErrUnavailable
	}
	b := &Bundle{claim: claim, consumer: consumer}
	b.self = b
	for _, p := range selected.Initiators {
		a := p.Authentication
		c := Credential{InitiatorName: p.Name, Mode: a.Mode, InitiatorUser: a.InitiatorUser, Incoming: newSecret(values[a.InitiatorSecretRef]), TargetUser: a.TargetUser}
		if a.Mode == "mutual-chap" {
			c.Outgoing = newSecret(values[a.TargetSecretRef])
		}
		b.peers = append(b.peers, c)
	}
	keep = true
	return b, nil
}
func nilConsumer(c Consumer) bool {
	if c == nil {
		return true
	}
	v := reflect.ValueOf(c)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	}
	return false
}
func (b *Bundle) verifyLocked(ctx context.Context) error {
	if b.released {
		return ErrClosed
	}
	if b.review {
		return ErrReview
	}
	if ctx == nil {
		return ErrInvalid
	}
	if ctx.Err() != nil {
		return ErrUnavailable
	}
	if os.Geteuid() != 0 || b.claim.Verify(ctx) != nil {
		b.review = true
		return ErrReview
	}
	return nil
}
func (b *Bundle) Verify(ctx context.Context) error {
	if b == nil || b.self != b {
		return ErrInvalid
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.verifyLocked(ctx)
}
func (b *Bundle) Prepare(ctx context.Context) error {
	if b == nil || b.self != b {
		return ErrInvalid
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.verifyLocked(ctx); err != nil {
		return err
	}
	if b.prepared {
		return ErrBusy
	}
	b.prepared = true                              // Even an uncertain/failed prepare is never repeated.
	peers := append([]Credential(nil), b.peers...) // Backend cannot replace owned buffers.
	if b.consumer.PrepareCredentials(ctx, peers) != nil || b.verifyLocked(ctx) != nil {
		b.review = true
		return ErrReview
	}
	return nil
}

// Release is ONLY a claim/buffer release, never a stop or proof of no borrowers.
// The containing private lifecycle calls it after confirmed teardown. Review
// permits that explicit release but never another Prepare. Wiping is best effort
// for owned buffers only: JSON/runtime/backend copies are not guaranteed erased.
func (b *Bundle) Release() error {
	if b == nil || b.self != b {
		return ErrInvalid
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.released {
		return nil
	}
	if b.claim.Release() != nil {
		b.review = true
		return ErrReview
	}
	for _, p := range b.peers {
		p.Incoming.wipe()
		p.Outgoing.wipe()
	}
	b.consumer = nil
	b.released = true
	return nil
}
