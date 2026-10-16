// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package policytransaction prototypes a private operation bundle. The portable
// codec grants no authority; the only writer is a disposable QEMU-tagged fixture.
package policytransaction

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/configjson"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/policyevidence"
)

const maxBundleBytes = 896 << 10
const bundleFormat = "phantowd-policy-operation-bundle-experimental"

var (
	ErrInvalid     = errors.New("invalid experimental policy transaction")
	ErrReview      = errors.New("experimental policy transaction requires review; no retry")
	ErrAttempted   = errors.New("experimental policy transaction already attempted")
	ErrUnsupported = errors.New("experimental policy transaction unsupported")
	ErrPrivate     = errors.New("experimental policy transaction is private")
)

// Private data, never an authority/confirmation token. Exact historical base
// bytes are base64 rather than RawMessage, which JSON marshaling may compact.
type bundle struct {
	installation          string
	revision              uint64
	base, intent, receipt []byte
}
type bundleWire struct {
	Format        string `json:"format"`
	SchemaVersion int    `json:"schema_version"`
	Revision      uint64 `json:"revision"`
	Phase         string `json:"phase"`
	Installation  string `json:"installation_id"`
	Base          string `json:"base"`
	Intent        string `json:"intent"`
	Receipt       string `json:"receipt"`
}

func (b bundle) validate() error {
	if len(b.base) == 0 || len(b.base) > naspolicy.MaxInputBytes || len(b.intent) == 0 || len(b.intent) > policyevidence.MaxRecordBytes || len(b.receipt) > policyevidence.MaxRecordBytes ||
		(b.revision != 1 && b.revision != 2) || (b.revision == 1) != (len(b.receipt) == 0) {
		return ErrInvalid
	}
	d, err := policyevidence.Match(policyevidence.Evidence{InstallationID: b.installation,
		Current: policyevidence.Slot{State: policyevidence.Present, Data: b.base},
		Intent:  policyevidence.Slot{State: policyevidence.Present, Data: b.intent}, Receipt: policyevidence.Slot{State: policyevidence.Absent}})
	if err != nil || d.Kind() != policyevidence.IntentBaseObserved {
		return ErrInvalid
	}
	if b.revision == 2 {
		i, e1 := policyevidence.DecodeIntent(bytes.NewReader(b.intent))
		r, e2 := policyevidence.DecodeReceipt(bytes.NewReader(b.receipt))
		// The two private values contain declarations, NOT success capabilities.
		if e1 != nil || e2 != nil || r != policyevidence.Receipt(i) {
			return ErrInvalid
		}
	}
	return nil
}
func (b bundle) MarshalJSON() ([]byte, error) {
	if b.validate() != nil {
		return nil, ErrInvalid
	}
	phase := "intent"
	if b.revision == 2 {
		phase = "local-confirmed"
	}
	data, err := json.Marshal(bundleWire{bundleFormat, 1, b.revision, phase, b.installation,
		base64.StdEncoding.EncodeToString(b.base), base64.StdEncoding.EncodeToString(b.intent), base64.StdEncoding.EncodeToString(b.receipt)})
	if err != nil || len(data) > maxBundleBytes {
		return nil, ErrInvalid
	}
	return data, nil
}
func canonicalBytes(s string, limit int, empty bool) ([]byte, error) {
	if empty && s == "" {
		return nil, nil
	}
	if len(s) > base64.StdEncoding.EncodedLen(limit) || !empty && s == "" {
		return nil, ErrInvalid
	}
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || len(b) > limit || base64.StdEncoding.EncodeToString(b) != s {
		clear(b)
		return nil, ErrInvalid
	}
	return b, nil
}
func decodeBundle(input io.Reader) (bundle, error) {
	if input == nil {
		return bundle{}, ErrInvalid
	}
	data, err := io.ReadAll(io.LimitReader(input, maxBundleBytes+1))
	if err != nil {
		clear(data)
		return bundle{}, ErrInvalid
	}
	defer clear(data)
	if _, err := configjson.DecodeEnvelope(data, maxBundleBytes, 2, "format", "schema_version", "revision", "phase", "installation_id", "base", "intent", "receipt"); err != nil {
		return bundle{}, ErrInvalid
	}
	var w bundleWire
	if json.Unmarshal(data, &w) != nil || w.Format != bundleFormat || w.SchemaVersion != 1 ||
		(w.Revision != 1 && w.Revision != 2) || (w.Revision == 1 && w.Phase != "intent") || (w.Revision == 2 && w.Phase != "local-confirmed") {
		return bundle{}, ErrInvalid
	}
	b := bundle{installation: w.Installation, revision: w.Revision}
	b.base, err = canonicalBytes(w.Base, naspolicy.MaxInputBytes, false)
	if err == nil {
		b.intent, err = canonicalBytes(w.Intent, policyevidence.MaxRecordBytes, false)
	}
	if err == nil {
		b.receipt, err = canonicalBytes(w.Receipt, policyevidence.MaxRecordBytes, true)
	}
	if err != nil || b.validate() != nil {
		b.clear()
		return bundle{}, ErrInvalid
	}
	return b, nil
}
func (b *bundle) clear() { clear(b.base); clear(b.intent); clear(b.receipt); *b = bundle{} }
func (bundle) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "experimental-policy-bundle{private}")
}

func intentBundle(installation string, p policyevidence.Prepared) (bundle, error) {
	base, err := p.BaseBytes()
	if err != nil {
		return bundle{}, ErrInvalid
	}
	i, err := p.Intent()
	if err != nil {
		clear(base)
		return bundle{}, ErrInvalid
	}
	wire, err := policyevidence.EncodeIntent(i)
	b := bundle{installation: installation, revision: 1, base: base, intent: wire}
	if err != nil || b.validate() != nil {
		b.clear()
		return bundle{}, ErrInvalid
	}
	return b, nil
}

// Declaration only. The fixture writer calls this AFTER verified policy commit
// and exact readback. The codec itself cannot prove any earlier syscall return.
func confirmedBundle(b bundle) (bundle, error) {
	if b.revision != 1 || b.validate() != nil {
		return bundle{}, ErrInvalid
	}
	i, err := policyevidence.DecodeIntent(bytes.NewReader(b.intent))
	if err != nil {
		return bundle{}, ErrInvalid
	}
	r, err := policyevidence.EncodeReceipt(policyevidence.Receipt(i))
	if err != nil {
		return bundle{}, ErrInvalid
	}
	next := bundle{installation: b.installation, revision: 2, base: bytes.Clone(b.base), intent: bytes.Clone(b.intent), receipt: r}
	if next.validate() != nil {
		next.clear()
		return bundle{}, ErrInvalid
	}
	return next, nil
}
