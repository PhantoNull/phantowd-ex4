//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"golang.org/x/sys/unix"
)

// Preserve originals on any uncertain failure until this disposable VM exits.
var nfsTableProbeRetainedQEMU any

func probeNFSTableQEMU(ctx context.Context, inputs *NFSInputsQEMU, candidate fileserviceplan.NFSv3Candidate) (result error) {
	if !inputs.valid() || nfsCodeGuardQEMU() != nil {
		return ErrInvalid
	}
	s, err := inputs.code.enter(ctx)
	if err != nil {
		return err
	}
	defer s.leave()
	var child *processowner.CaptureOwner
	var bootstrap, input *os.File
	phase := "inputs"
	defer func() {
		if result != nil {
			s.review, s.cause = true, result
			nfsTableProbeRetainedQEMU = struct {
				inputs           *NFSInputsQEMU
				child            *processowner.CaptureOwner
				bootstrap, input *os.File
				err              error
			}{inputs, child, bootstrap, input, result}
			fmt.Fprintf(os.Stderr, "PHANTOWD_NFS_TABLE_FAILURE phase=%s\n", phase)
		}
	}()
	if s.review || s.closed || s.configuration == nil || s.state == nil || s.revalidate(ctx) != nil {
		return ErrReviewRequired
	}
	// The containing input lifetime stays busy until all child work is settled.
	if !errors.Is(inputs.Close(), processowner.ErrBusy) {
		return ErrMismatch
	}
	before, err := retainedFixtureFDCount()
	if err != nil {
		return err
	}
	bootstrap, err = os.Open("/usr/sbin/phantowd-nfs-table-bootstrap")
	if err != nil {
		return err
	}
	const stdinPath = "/run/phantowd-nfs-table-empty-input"
	created, err := os.OpenFile(stdinPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
	if err != nil {
		return err
	}
	if err := created.Close(); err != nil {
		return err
	}
	input, err = os.Open(stdinPath)
	if err != nil {
		return err
	}
	program := s.code.files["usr/sbin/exportfs"]
	for _, alias := range s.code.plan.aliases {
		if alias.Path == "usr/sbin/exportfs" {
			program = s.code.files[alias.Target]
		}
	}
	if program == nil {
		return ErrMismatch
	}
	phase = "capture-constructor-rollback"
	constructorBefore, err := retainedFixtureFDCount()
	if err != nil {
		return err
	}
	// Immutable configuration cannot masquerade as writable state. Refusal
	// must release only independent duplicates, not consume original inputs.
	child, err = processowner.NewNFSTableCaptureQEMU(bootstrap, input, [4]*os.File{
		s.code.root, s.configuration.contents.root, s.configuration.contents.root, program,
	})
	if child != nil || !errors.Is(err, processowner.ErrInvalid) || errors.Is(err, processowner.ErrReviewRequired) {
		return errors.Join(ErrMismatch, err)
	}
	if after, err := retainedFixtureFDCount(); err != nil || after != constructorBefore || s.revalidate(ctx) != nil {
		return ErrMismatch
	}
	_, table, _, err := candidate.Documents()
	if err != nil {
		return err
	}
	etab := filepath.Join(nfsStateViewQEMU, "nfs/etab")
	// Synthetic table only; no data root exists in the child's view. Neither
	// listing is an export publication. Every capture is a distinct single use.
	for _, populated := range []bool{true, false} {
		phase = "seed"
		data := []byte(nil)
		if populated {
			data = []byte(table)
		}
		if err := os.WriteFile(etab, data, 0600); err != nil {
			return err
		}
		var prior unix.Stat_t
		if unix.Lstat(etab, &prior) != nil {
			return ErrMismatch
		}
		phase = "construct"
		child, err = processowner.NewNFSTableCaptureQEMU(bootstrap, input, [4]*os.File{
			s.code.root, s.configuration.contents.root, s.state.root, program,
		})
		if err != nil {
			return err // Keep the ORIGINAL construction-review error chain.
		}
		if err := s.revalidate(ctx); err != nil {
			return err
		}
		phase = "capture"
		captured, err := child.Capture(ctx)
		if err != nil {
			return err // No repeated capture or teardown attempt on uncertainty.
		}
		phase = "result"
		const handoff = "PHANTOWD_NFS_TABLE_HANDOFF private_view=true capabilities_zero=true fixed_exportfs=true\n"
		if captured.Kind != processowner.CaptureExited || captured.ExitCode != 0 ||
			string(captured.Stderr) != handoff || !nfsTableOutputQEMU(captured.Stdout, populated) {
			// Disposable synthetic data only, bounded by CaptureOwner's limits.
			fmt.Fprintf(os.Stderr, "NFS table fixture result populated=%t kind=%d exit=%d stdout=%q stderr=%q\n", populated, captured.Kind, captured.ExitCode, captured.Stdout, captured.Stderr)
			return ErrMismatch
		}
		phase = "settlement"
		settled, err := child.Settled(ctx)
		if err != nil || !settled {
			return errors.Join(ErrReviewRequired, err)
		}
		if err := child.Close(ctx); err != nil {
			return err
		}
		child = nil
		phase = "unchanged-table"
		var after unix.Stat_t
		actual, err := os.ReadFile(etab)
		if err != nil || unix.Lstat(etab, &after) != nil || prior.Dev != after.Dev || prior.Ino != after.Ino ||
			prior.Mode != after.Mode || prior.Size != after.Size || prior.Mtim != after.Mtim || prior.Ctim != after.Ctim || !bytes.Equal(actual, data) {
			return ErrMismatch
		}
		if err := s.revalidate(ctx); err != nil {
			return err
		}
	}
	phase = "normal-close"
	if err := bootstrap.Close(); err != nil {
		return err
	}
	bootstrap = nil
	if err := input.Close(); err != nil {
		return err
	}
	input = nil
	if after, err := retainedFixtureFDCount(); err != nil || after != before {
		return ErrMismatch
	}
	// Exact owned fixture leaves only, AFTER both process groups and all capture
	// references are gone. Do not adopt, repair or clean nonfresh product state.
	entries, err := os.ReadDir(filepath.Dir(etab))
	if err != nil || len(entries) != 2 || entries[0].Name() != ".etab.lock" || entries[1].Name() != "etab" {
		return ErrMismatch
	}
	var lock unix.Stat_t
	if unix.Lstat(filepath.Join(filepath.Dir(etab), ".etab.lock"), &lock) != nil ||
		lock.Mode != unix.S_IFREG|0600 || lock.Size != 0 || lock.Nlink != 1 || lock.Uid != 0 || lock.Gid != 0 {
		return ErrMismatch
	}
	for _, path := range []string{etab, filepath.Join(filepath.Dir(etab), ".etab.lock"), stdinPath} {
		if err := os.Remove(path); err != nil {
			return err
		}
	}
	if err := s.revalidate(ctx); err != nil {
		return err
	}
	fmt.Println("PHANTOWD_NFS_TABLE_READY populated=true empty_control=true table_unchanged=true original_inputs=true close_excluded=true constructor_rollback=true private_view=true capabilities_zero=true stop_reaped=true fd_balance=true command=exportfs-s services=false kernel_control=false scope=qemu-only")
	return nil
}
