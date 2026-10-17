//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policyevidencefs

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicystore"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/policyevidence"
)

// Only called inside the existing fresh verified tmpfs fixture. Receipts are
// invented observations, not writer results, synchronization or recovery proof.
func exerciseHistoryObservationQEMU(ctx context.Context, root string, base, current, intent, receipt []byte) error {
	const installation = "11111111222233334444555555555555"
	c, err := naspolicy.Decode(bytes.NewReader(current))
	if err != nil {
		return ErrInvalid
	}
	c.Revision, c.FileServices.Revision = 3, 3
	c.FileServices.Shares.Revision, c.FileServices.NFS.Revision, c.FileServices.NFS.VolumeRevision = 3, 3, 3
	c.ISCSI.Revision, c.ISCSI.VolumeRevision = 3, 3
	p, err := policyevidence.Prepare(installation, current, c)
	if err != nil {
		return err
	}
	final, err := p.CandidateBytes()
	if err != nil {
		return err
	}
	i, err := p.Intent()
	if err != nil {
		return err
	}
	second, err := policyevidence.EncodeIntent(i)
	if err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(second, &fields) != nil {
		return ErrInvalid
	}
	fields["format"], fields["phase"] = json.RawMessage(`"phantowd-nas-policy-receipt"`), json.RawMessage(`"local-confirmed"`)
	secondReceipt, err := json.Marshal(fields)
	if err != nil {
		return ErrInvalid
	}
	wires, names := make([][]byte, 2), make([]string, 2)
	for n, record := range []struct{ base, intent, receipt []byte }{{base, intent, receipt}, {current, second, secondReceipt}} {
		// Independent test-only extraction; production uses the strict decoder.
		var naming struct {
			OperationID string `json:"operation_id"`
		}
		if json.Unmarshal(record.intent, &naming) != nil || naming.OperationID == "" {
			return ErrInvalid
		}
		names[n] = naming.OperationID + ".json"
		wires[n], err = json.Marshal(map[string]any{"format": "phantowd-policy-operation-bundle-experimental", "schema_version": 1,
			"revision": 2, "phase": "local-confirmed", "installation_id": installation,
			"base": base64.StdEncoding.EncodeToString(record.base), "intent": base64.StdEncoding.EncodeToString(record.intent), "receipt": base64.StdEncoding.EncodeToString(record.receipt)})
		if err != nil {
			return ErrInvalid
		}
	}
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return ErrIO
	}
	makeLayout := func(name string) (string, error) {
		dir := filepath.Join(root, "history-"+name)
		if os.Mkdir(dir, 0700) != nil || os.Mkdir(filepath.Join(dir, "policy"), 0700) != nil || os.Mkdir(filepath.Join(dir, "operations"), 0700) != nil ||
			os.WriteFile(filepath.Join(dir, "policy/nas-services.json"), final, 0600) != nil {
			return "", ErrIO
		}
		for n := range wires {
			if os.WriteFile(filepath.Join(dir, "operations", names[n]), wires[n], 0600) != nil {
				return "", ErrIO
			}
		}
		return dir, nil
	}
	if err := exerciseCloseFaultMatrixQEMU(ctx, 6, func(boundary int, after bool) (*Observer, error) {
		dir, err := makeLayout(fmt.Sprintf("close-%d-%t", boundary, after))
		if err != nil {
			return nil, err
		}
		return OpenHistory(ctx, dir, installation, base)
	}); err != nil {
		return err
	}
	for _, scenario := range []string{"healthy", "pending", "name-mismatch", "substitution", "mixed", "count-limit", "over-count", "over-budget"} {
		dir, err := makeLayout(scenario)
		if err != nil {
			return err
		}
		if scenario == "pending" || scenario == "mixed" {
			name := historyPending
			if scenario == "mixed" {
				name = "operation.json"
			}
			if os.WriteFile(filepath.Join(dir, "operations", name), []byte("not parsed"), 0600) != nil {
				return ErrIO
			}
		}
		if scenario == "name-mismatch" && os.Rename(filepath.Join(dir, "operations", names[0]), filepath.Join(dir, "operations", "ffffffffffffffffffffffffffffffff.json")) != nil {
			return ErrIO
		}
		if scenario == "count-limit" || scenario == "over-count" || scenario == "over-budget" {
			count, size := 16, 2
			if scenario == "over-count" {
				count = 17
			}
			if scenario == "over-budget" {
				count, size = 8, 600000
			}
			for _, name := range names {
				if os.Remove(filepath.Join(dir, "operations", name)) != nil {
					return ErrIO
				}
			}
			for n := 1; n <= count; n++ {
				file, err := os.OpenFile(filepath.Join(dir, "operations", fmt.Sprintf("%032x.json", n)), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
				if err != nil {
					return ErrIO
				}
				truncateErr, closeErr := file.Truncate(int64(size)), file.Close()
				if truncateErr != nil || closeErr != nil {
					return ErrIO
				}
			}
		}
		checkpoint := bytes.Clone(base)
		a, err := OpenHistory(ctx, dir, installation, checkpoint)
		if scenario == "mixed" || scenario == "over-count" || scenario == "over-budget" {
			if a != nil {
				_ = a.Close()
				return ErrReview
			}
			if !errors.Is(err, ErrUnsafe) {
				return ErrReview
			}
			continue
		}
		if err != nil {
			return err
		}
		if err := exerciseOpenHistoryQEMU(ctx, a, dir, scenario, checkpoint, names[0], wires[0]); err != nil {
			return err
		}
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(before) != len(after) {
		return ErrReview
	}
	fmt.Println("PHANTOWD_POLICY_HISTORY_FS_READY records=2 original_locks=true name_bound=true checkpoint_owned=true pending_metadata_only=true sticky_review=true readonly=true admission=false scope=temporary-qemu-only")
	return nil
}

func exerciseOpenHistoryQEMU(ctx context.Context, a *Observer, dir, scenario string, checkpoint []byte, name string, wire []byte) (result error) {
	defer func() {
		if a.Close() != nil {
			result = ErrReview
		}
	}()
	checkpoint[0] = '!'
	if scenario == "count-limit" {
		return nil
	} // constructor bound, not record validity
	reads := 0
	if scenario == "pending" {
		a.state.readAt = func(*os.File, []byte, int64) (int, error) { reads++; return 0, ErrIO }
	}
	if scenario == "substitution" {
		path := filepath.Join(dir, "operations", name)
		if os.Rename(path, filepath.Join(dir, "original-record")) != nil || os.WriteFile(path, wire, 0600) != nil {
			return ErrIO
		}
	}
	for iteration := 0; iteration < 2; iteration++ {
		d, err := a.Observe(ctx)
		if scenario == "healthy" {
			if err != nil || d.Kind() != policyevidence.LocalConfirmationObserved {
				return ErrReview
			}
		} else if !errors.Is(err, ErrReview) || d.Kind() != "" || reads != 0 {
			return ErrReview
		}
		other, err := naspolicystore.Open(filepath.Join(dir, "policy"))
		if other != nil {
			_ = other.Close()
			return ErrReview
		}
		if !errors.Is(err, naspolicystore.ErrBusy) {
			return ErrReview
		}
		if iteration == 0 && scenario == "substitution" {
			if os.Remove(filepath.Join(dir, "operations", name)) != nil || os.Rename(filepath.Join(dir, "original-record"), filepath.Join(dir, "operations", name)) != nil {
				return ErrIO
			}
		}
	}
	return nil
}
