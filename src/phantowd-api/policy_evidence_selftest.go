//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/policyevidence"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/policytransaction"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/nfsconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

// Pure invented complete NAS before/after pair and private record bytes.
// No state, policy owner, filesystem collector, fsync, writer or HTTP is used.
func exerciseQEMUPolicyEvidence() error {
	c, err := naspolicy.Decode(strings.NewReader(qemuISCSIPreviewFixture))
	if err != nil {
		return errors.New("policy evidence synthetic NAS fixture unavailable")
	}
	var f struct {
		Shares shareconfig.Config `json:"shares"`
		NFS    nfsconfig.Policy   `json:"nfs"`
	}
	if json.Unmarshal([]byte(qemuFileServicePreviewFixture), &f) != nil {
		return errors.New("policy evidence synthetic file fixture unavailable")
	}
	c.FileServices = fileservice.Config{Format: fileservice.ConfigFormat, SchemaVersion: 1, Shares: f.Shares, NFS: f.NFS}
	setRevision := func(revision uint64) {
		c.Revision, c.FileServices.Revision, c.FileServices.Shares.Revision = revision, revision, revision
		c.FileServices.NFS.Revision, c.FileServices.NFS.VolumeRevision = revision, revision
		c.ISCSI.Revision, c.ISCSI.VolumeRevision = revision, revision
	}
	setRevision(7)
	base, err := json.Marshal(c)
	if err != nil || c.Validate() != nil {
		return errors.New("policy evidence synthetic base invalid")
	}
	setRevision(8)
	return exercisePolicyEvidencePair(base, c)
}

func exercisePolicyEvidencePair(base []byte, next naspolicy.Config) error {
	// Desired state only, not a target operation.
	next.ISCSI.Targets[0].State = "disabled"
	after, err := json.Marshal(next)
	if err != nil || next.Validate() != nil {
		return errors.New("policy evidence synthetic candidate invalid")
	}
	hash := func(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
	const installation = "11111111222233334444555555555555"
	const operation = "aaaaaaaabbbbccccddddeeeeeeeeeeee"
	record := map[string]any{"format": policyevidence.IntentFormat, "schema_version": 1,
		"installation_id": installation, "operation_id": operation, "base_revision": uint64(7), "next_revision": uint64(8),
		"base_sha256": hash(base), "next_sha256": hash(after)}
	intent, err := json.Marshal(record)
	if err != nil {
		return errors.New("policy evidence synthetic intent unavailable")
	}
	record["format"], record["phase"] = policyevidence.ReceiptFormat, "local-confirmed"
	receipt, err := json.Marshal(record)
	if err != nil {
		return errors.New("policy evidence synthetic receipt unavailable")
	}
	e := policyevidence.Evidence{InstallationID: installation, Intent: policyevidence.Slot{State: policyevidence.Present, Data: intent},
		Receipt: policyevidence.Slot{State: policyevidence.Present, Data: receipt}, Current: policyevidence.Slot{State: policyevidence.Present, Data: after}}
	for _, tc := range []struct {
		change func(*policyevidence.Evidence)
		want   policyevidence.Kind
	}{
		{func(*policyevidence.Evidence) {}, policyevidence.LocalConfirmationObserved},
		{func(e *policyevidence.Evidence) { e.Receipt = policyevidence.Slot{State: policyevidence.Absent} }, policyevidence.PublicationUnconfirmed},
		{func(e *policyevidence.Evidence) {
			e.Receipt = policyevidence.Slot{State: policyevidence.Absent}
			e.Current.Data = base
		}, policyevidence.IntentBaseObserved},
		{func(e *policyevidence.Evidence) { e.Intent = policyevidence.Slot{State: policyevidence.Absent} }, policyevidence.InconsistentEvidence},
		{func(e *policyevidence.Evidence) {
			e.Intent = policyevidence.Slot{State: policyevidence.Absent}
			e.Receipt = policyevidence.Slot{State: policyevidence.Absent}
		}, policyevidence.NoRecordedOperation},
		{func(e *policyevidence.Evidence) { e.Receipt = policyevidence.Slot{} }, policyevidence.IncompleteEvidence},
		{func(e *policyevidence.Evidence) { e.Current.Data = append(append([]byte{}, after...), '\n') }, policyevidence.InconsistentEvidence},
		{func(e *policyevidence.Evidence) { e.InstallationID = operation }, policyevidence.InconsistentEvidence},
	} {
		input := e
		tc.change(&input)
		d, err := policyevidence.Match(input)
		if err != nil || d.Kind() != tc.want {
			return errors.New("policy evidence synthetic match failed")
		}
		if _, err := json.Marshal(d); !errors.Is(err, policyevidence.ErrPrivate) {
			return errors.New("policy evidence synthetic diagnosis JSON admitted")
		}
	}
	for _, input := range [][]byte{intent, append(append([]byte{}, intent...), []byte("{}")...), bytes.Repeat([]byte(" "), policyevidence.MaxRecordBytes+1)} {
		decoded, err := policyevidence.DecodeIntent(bytes.NewReader(input))
		if bytes.Equal(input, intent) {
			encoded, encodeErr := policyevidence.EncodeIntent(decoded)
			if err != nil || encodeErr != nil || len(encoded) > policyevidence.MaxRecordBytes {
				return errors.New("policy evidence synthetic codec failed")
			}
			if _, err := json.Marshal(decoded); !errors.Is(err, policyevidence.ErrPrivate) {
				return errors.New("policy evidence synthetic intent JSON admitted")
			}
			if strings.Contains(fmt.Sprintf("%#v", decoded), installation) {
				return errors.New("policy evidence synthetic formatting disclosed identity")
			}
		} else if err != policyevidence.ErrInvalid || decoded != (policyevidence.Intent{}) {
			return errors.New("policy evidence malformed input admitted")
		}
	}
	return policytransaction.ExerciseBundleHistoryQEMU(installation, base, next)
}
