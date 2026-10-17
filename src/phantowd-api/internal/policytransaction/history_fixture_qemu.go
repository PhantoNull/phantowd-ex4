//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policytransaction

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/policyevidence"
)

// ExerciseBundleHistoryQEMU is synthetic memory-only acceptance, not an opener,
// writer, persisted history or receipt of successful filesystem operations.
func ExerciseBundleHistoryQEMU(installation string, base []byte, next naspolicy.Config) error {
	prepared, err := policyevidence.Prepare(installation, base, next)
	if err != nil {
		return ErrInvalid
	}
	firstIntent, err := intentBundle(installation, prepared)
	if err != nil {
		return ErrInvalid
	}
	defer firstIntent.clear()
	first, err := confirmedBundle(firstIntent)
	if err != nil {
		return ErrInvalid
	}
	defer first.clear()
	after, err := prepared.CandidateBytes()
	if err != nil {
		return ErrInvalid
	}
	defer clear(after)
	future, err := naspolicy.Decode(bytes.NewReader(after))
	if err != nil || future.Revision+1 == 0 {
		return ErrInvalid
	}
	n := future.Revision + 1
	future.Revision, future.FileServices.Revision, future.FileServices.Shares.Revision = n, n, n
	future.FileServices.NFS.Revision, future.FileServices.NFS.VolumeRevision = n, n
	future.ISCSI.Revision, future.ISCSI.VolumeRevision = n, n
	secondPrepared, err := policyevidence.Prepare(installation, after, future)
	if err != nil {
		return ErrInvalid
	}
	secondIntent, err := intentBundle(installation, secondPrepared)
	if err != nil {
		return ErrInvalid
	}
	defer secondIntent.clear()
	second, err := confirmedBundle(secondIntent)
	if err != nil {
		return ErrInvalid
	}
	defer second.clear()
	current, err := secondPrepared.CandidateBytes()
	if err != nil {
		return ErrInvalid
	}
	defer clear(current)
	one, err := json.Marshal(first)
	if err != nil {
		return ErrInvalid
	}
	defer clear(one)
	two, err := json.Marshal(second)
	if err != nil {
		return ErrInvalid
	}
	defer clear(two)
	unconfirmed, err := json.Marshal(secondIntent)
	if err != nil {
		return ErrInvalid
	}
	defer clear(unconfirmed)
	present := func(data []byte) policyevidence.Slot {
		return policyevidence.Slot{State: policyevidence.Present, Data: data}
	}
	for _, tc := range []struct {
		current    policyevidence.Slot
		operations []policyevidence.Slot
		want       policyevidence.Kind
	}{
		{present(current), []policyevidence.Slot{present(two), present(one)}, policyevidence.LocalConfirmationObserved},
		{present(current), []policyevidence.Slot{present(two)}, policyevidence.InconsistentEvidence},
		{present(current), []policyevidence.Slot{present(one), present(one)}, policyevidence.InconsistentEvidence},
		{present(current), []policyevidence.Slot{present(one), present(unconfirmed)}, policyevidence.PublicationUnconfirmed},
		{present(after), []policyevidence.Slot{present(one), present(unconfirmed)}, policyevidence.IntentBaseObserved},
		{present(current), []policyevidence.Slot{present(one), {}}, policyevidence.IncompleteEvidence},
	} {
		d, err := MatchBundleHistoryObservation(installation, present(base), tc.current, tc.operations)
		if err != nil || d.Kind() != tc.want {
			return ErrReview
		}
		if _, err := json.Marshal(d); !errors.Is(err, policyevidence.ErrPrivate) {
			return ErrPrivate
		}
	}
	if d, err := MatchBundleHistoryObservation(installation, present(base), present(current), []policyevidence.Slot{present(one), present([]byte(`{"malformed":true}`))}); !errors.Is(err, ErrInvalid) || d != (policyevidence.Diagnosis{}) {
		return ErrReview
	}
	if strings.Contains(fmt.Sprintf("%#v", first), installation) {
		return ErrPrivate
	}
	fmt.Println("PHANTOWD_POLICY_HISTORY_READY records=2 anchored=true gap_refused=true duplicate_refused=true uncertain_tail=true private=true readonly=true admission=false scope=synthetic-memory-only")
	return nil
}
