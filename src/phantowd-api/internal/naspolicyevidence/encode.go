// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package naspolicyevidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
)

// EncodeOperation prepares unpublished record bytes, not confirmation or writer
// authority. The trusted coordinator must allocate the operation ID, reject its
// reuse and publish the receipt only after verified local publication. This pure
// codec does not establish provenance, synchronize files or authorize recovery.
// Inputs remain caller-owned and must not be mutated concurrently.
func EncodeOperation(installationID, operationID string, base, next []byte) (intent, receipt []byte, err error) {
	if !canonicalHex(installationID, 32, true) || !canonicalHex(operationID, 32, true) {
		return nil, nil, errInvalid
	}
	previous, err := naspolicy.Decode(bytes.NewReader(base))
	if err != nil {
		return nil, nil, errInvalid
	}
	candidate, err := naspolicy.Decode(bytes.NewReader(next))
	if err != nil {
		return nil, nil, errInvalid
	}
	if fileservice.ValidateRetainedNFSBindings(previous.FileServices, candidate.FileServices) != nil {
		return nil, nil, errInvalid
	}
	before, after := sha256.Sum256(base), sha256.Sum256(next)
	r := record{Format: IntentFormat, SchemaVersion: 1, InstallationID: installationID, OperationID: operationID,
		BaseRevision: previous.Revision, NextRevision: candidate.Revision,
		BaseSHA256: hex.EncodeToString(before[:]), NextSHA256: hex.EncodeToString(after[:])}
	intent, err = json.Marshal(r)
	if err != nil {
		return nil, nil, errInvalid
	}
	if _, err := decode(intent, false); err != nil {
		return nil, nil, errInvalid
	}
	r.Format, r.Phase = ReceiptFormat, "local-confirmed"
	receipt, err = json.Marshal(r)
	if err != nil || len(receipt) > MaxRecordBytes {
		return nil, nil, errInvalid
	}
	return intent, receipt, nil
}
