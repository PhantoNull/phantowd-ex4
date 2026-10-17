//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policyevidencefs

import (
	"bytes"
	"context"
	"slices"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/policyevidence"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/policytransaction"
)

const historyPending = ".history.pending"

// OpenHistory fixes the experimental operations/<operation-ID>.json profile
// and an independently trusted exact checkpoint for the entire lifetime. It
// never infers that checkpoint from these records or adopts a writer. All Open
// cleanup/lock/provenance requirements apply; a nonnil handle WITH error is
// reviewed retained state, never successful admission.
func OpenHistory(ctx context.Context, directory, installation string, checkpoint []byte) (*Observer, error) {
	if len(checkpoint) == 0 {
		return nil, ErrInvalid
	}
	return open(ctx, directory, installation, false, checkpoint)
}

func validateHistoryCheckpoint(installation string, checkpoint []byte) error {
	if len(checkpoint) == 0 || len(checkpoint) > naspolicy.MaxInputBytes {
		return ErrInvalid
	}
	slot := policyevidence.Slot{State: policyevidence.Present, Data: checkpoint}
	d, err := policyevidence.MatchHistory(installation, slot, slot, nil)
	if err != nil || d.Kind() != policyevidence.NoRecordedOperation {
		return ErrInvalid
	}
	return nil
}

func (s *state) initializeHistoryCheckpoint(checkpoint []byte) {
	s.historyProfile = true
	s.checkpoint = bytes.Clone(checkpoint)
}

func (s *state) fileObjects() []object {
	if s.historyProfile {
		return s.historyFiles
	}
	return s.files[:]
}

func (s *state) prepareHistoryRoles() error {
	names := make([]string, 0, len(s.names[2]))
	for name := range s.names[2] {
		if name != historyPending {
			names = append(names, name)
		}
	}
	if len(names) > policyevidence.MaxHistoryOperations {
		return ErrUnsafe
	}
	slices.Sort(names) // deterministic IO only; chronology comes from bound tuples.
	s.historyRoles = []roleSpec{{1, "nas-services.json", naspolicy.MaxInputBytes}}
	for _, name := range names {
		s.historyRoles = append(s.historyRoles, roleSpec{2, name, policytransaction.MaxObservedBundleBytes})
	}
	remaining := uint64(policyevidence.MaxHistoryInputBytes - len(s.checkpoint))
	for _, spec := range s.historyRoles {
		if st, found := s.names[spec.parent][spec.name]; found {
			if st.size == 0 || st.size > uint64(spec.limit) || st.size > remaining {
				return ErrUnsafe
			}
			remaining -= st.size
		}
	}
	s.historyFiles = make([]object, len(s.historyRoles))
	return nil
}

func (s *state) matchHistory(slots []policyevidence.Slot) (policyevidence.Diagnosis, error) {
	entries := make([]policytransaction.NamedBundleObservation, len(slots)-1)
	for index := range entries {
		entries[index] = policytransaction.NamedBundleObservation{Name: s.historyRoles[index+1].name, Operation: slots[index+1]}
	}
	return policytransaction.MatchNamedBundleHistoryObservation(s.installation,
		policyevidence.Slot{State: policyevidence.Present, Data: s.checkpoint}, slots[0], entries)
}
