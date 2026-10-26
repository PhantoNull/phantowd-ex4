//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"

	e "github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicyevidence"
)

// Pure synthetic observations only; called after the enclosing guest guard.
func exerciseQEMUNASPolicyEvidence() error {
	base, baseErr := json.Marshal(qemuPersistentNASPolicy(1))
	next, nextErr := json.Marshal(qemuPersistentNASPolicy(2))
	const installation = "11111111111111111111111111111111"
	fields := map[string]any{"format": e.IntentFormat, "schema_version": 1, "installation_id": installation,
		"operation_id": "22222222222222222222222222222222", "base_revision": 1, "next_revision": 2,
		"base_sha256": fmt.Sprintf("%x", sha256.Sum256(base)), "next_sha256": fmt.Sprintf("%x", sha256.Sum256(next))}
	intent, intentErr := json.Marshal(fields)
	fields["format"], fields["phase"] = e.ReceiptFormat, "local-confirmed"
	receipt, receiptErr := json.Marshal(fields)
	if err := errors.Join(baseErr, nextErr, intentErr, receiptErr); err != nil {
		return err
	}
	for _, tc := range []struct {
		current, intent, receipt []byte
		complete                 bool
		want                     e.Kind
	}{
		{base, nil, nil, true, e.NoRecordedOperation},
		{base, intent, nil, true, e.UnconfirmedBase},
		{next, intent, nil, true, e.UnconfirmedPublication},
		{next, intent, receipt, true, e.MatchingLocalRecords},
		{base, intent, receipt, true, e.Inconsistent},
		{nil, intent, receipt, true, e.Unavailable},
		{[]byte("{truncated"), intent, receipt, true, e.InvalidPolicy},
		{next, append(append([]byte{}, intent...), '{', '}'), receipt, true, e.Inconsistent},
		{next, intent, receipt, false, e.Unavailable},
	} {
		if e.Inspect(installation, tc.current, tc.intent, tc.receipt, tc.complete) != tc.want {
			return errors.New("NAS operation evidence observation differs")
		}
	}
	fmt.Println("PHANTOWD_NAS_OPERATION_EVIDENCE_READY cases=9 exact_current=true strict_records=true effects=none scope=synthetic-qemu-only")
	return nil
}
