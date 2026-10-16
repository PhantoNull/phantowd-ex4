// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policytransaction

import (
	"bytes"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/policyevidence"
)

// MaxObservedBundleBytes is the fixed experimental bundle ceiling, not a
// caller-selected codec or a product storage compatibility commitment.
const MaxObservedBundleBytes = maxBundleBytes

// MatchBundleObservation compares caller-owned bytes without IO or effects.
// The caller must establish origin, completeness and absence of pending files;
// this function establishes none of them. Do not mutate input concurrently.
// Every diagnosis grants no action, including a matching local declaration:
// it proves neither earlier sync returns nor delivery of a browser response.
func MatchBundleObservation(installation string, current, operation policyevidence.Slot) (policyevidence.Diagnosis, error) {
	if (operation.State != policyevidence.Present && operation.State != policyevidence.Absent && operation.State != policyevidence.Unavailable) ||
		(operation.State == policyevidence.Present) != (len(operation.Data) > 0) || len(operation.Data) > MaxObservedBundleBytes {
		return policyevidence.Diagnosis{}, ErrInvalid
	}
	e := policyevidence.Evidence{InstallationID: installation, Current: current,
		Intent: policyevidence.Slot{State: policyevidence.Absent}, Receipt: policyevidence.Slot{State: policyevidence.Absent}}
	// Validate the expected ID and any present current policy even if operation
	// evidence is unavailable. Errors never return a partially useful diagnosis.
	if _, err := policyevidence.Match(e); err != nil {
		return policyevidence.Diagnosis{}, ErrInvalid
	}
	switch operation.State {
	case policyevidence.Unavailable:
		e.Intent.State = policyevidence.Unavailable
	case policyevidence.Present:
		b, err := decodeBundle(bytes.NewReader(operation.Data))
		if err != nil {
			return policyevidence.Diagnosis{}, ErrInvalid
		}
		defer b.clear()
		e.Intent = policyevidence.Slot{State: policyevidence.Present, Data: b.intent}
		if b.revision == 2 {
			e.Receipt = policyevidence.Slot{State: policyevidence.Present, Data: b.receipt}
		}
	}
	d, err := policyevidence.Match(e)
	if err != nil {
		return policyevidence.Diagnosis{}, ErrInvalid
	}
	return d, nil
}
