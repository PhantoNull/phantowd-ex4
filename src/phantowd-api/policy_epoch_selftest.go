//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/policyevidence"
)

// Declaration matching only: no epoch files, fsync, Close, consumer observation,
// boot classification, recovery, restart or service admission is performed.
func exercisePolicyEpochRecords(base, current []byte) error {
	const installation = "11111111222233334444555555555555"
	const epoch = "aaaaaaaabbbbccccddddeeeeeeeeeeee"
	fail := func() error { return errors.New("synthetic policy epoch declaration failed") }
	o, err := policyevidence.DeclareEpochOpening(installation, epoch, math.MaxUint64, base)
	if err != nil {
		return fail()
	}
	opening, err := policyevidence.EncodeEpochOpening(o)
	if err != nil {
		return fail()
	}
	c, err := policyevidence.DeclareEpochClosure(opening, current)
	if err != nil {
		return fail()
	}
	closure, err := policyevidence.EncodeEpochClosure(c)
	if err != nil {
		return fail()
	}
	for _, tc := range []struct {
		o, c, p policyevidence.Slot
		kind    policyevidence.EpochKind
	}{
		{policyevidence.Slot{State: policyevidence.Absent}, policyevidence.Slot{State: policyevidence.Absent}, policyevidence.Slot{State: policyevidence.Present, Data: current}, policyevidence.NoEpochRecorded},
		{policyevidence.Slot{State: policyevidence.Present, Data: opening}, policyevidence.Slot{State: policyevidence.Absent}, policyevidence.Slot{State: policyevidence.Present, Data: current}, policyevidence.OpenEpochObserved},
		{policyevidence.Slot{State: policyevidence.Present, Data: opening}, policyevidence.Slot{State: policyevidence.Present, Data: closure}, policyevidence.Slot{State: policyevidence.Present, Data: current}, policyevidence.ClosureMatchesCurrent},
		{policyevidence.Slot{State: policyevidence.Absent}, policyevidence.Slot{State: policyevidence.Present, Data: closure}, policyevidence.Slot{State: policyevidence.Present, Data: current}, policyevidence.InconsistentEpochEvidence},
		{policyevidence.Slot{}, policyevidence.Slot{State: policyevidence.Present, Data: closure}, policyevidence.Slot{State: policyevidence.Present, Data: current}, policyevidence.IncompleteEpochEvidence},
		{policyevidence.Slot{State: policyevidence.Present, Data: opening}, policyevidence.Slot{State: policyevidence.Present, Data: closure}, policyevidence.Slot{}, policyevidence.IncompleteEpochEvidence},
		{policyevidence.Slot{State: policyevidence.Present, Data: append(bytes.Clone(opening), '\n')}, policyevidence.Slot{State: policyevidence.Present, Data: closure}, policyevidence.Slot{State: policyevidence.Present, Data: current}, policyevidence.InconsistentEpochEvidence},
		{policyevidence.Slot{State: policyevidence.Present, Data: opening}, policyevidence.Slot{State: policyevidence.Present, Data: closure}, policyevidence.Slot{State: policyevidence.Present, Data: append(bytes.Clone(current), '\n')}, policyevidence.InconsistentEpochEvidence},
	} {
		d, err := policyevidence.MatchEpoch(installation, tc.o, tc.c, tc.p)
		if err != nil || d.Kind() != tc.kind {
			return fail()
		}
		if _, err := json.Marshal(d); !errors.Is(err, policyevidence.ErrPrivate) {
			return fail()
		}
	}
	if d, err := policyevidence.MatchEpoch(installation, policyevidence.Slot{State: policyevidence.Present, Data: []byte(`{}`)}, policyevidence.Slot{}, policyevidence.Slot{}); err != policyevidence.ErrInvalid || d.Kind() != "" {
		return fail()
	}
	if _, err := json.Marshal(o); !errors.Is(err, policyevidence.ErrPrivate) {
		return fail()
	}
	fmt.Println("PHANTOWD_POLICY_EPOCH_RECORD_READY cases=8 exact_binding=true declarations_only=true admission=false scope=synthetic-memory-only")
	return nil
}
