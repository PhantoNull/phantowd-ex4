//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/nfsconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
	"golang.org/x/sys/unix"
)

var nfsInputsProbeRetainedQEMU []*NFSInputsQEMU
var nfsInputsProbeErrorQEMU error

func nfsInputsFixtureCandidateQEMU(network string) (fileserviceplan.NFSv3Candidate, error) {
	registry, err := serviceaccounts.New(1000, 2000)
	if err != nil {
		return fileserviceplan.NFSv3Candidate{}, err
	}
	const uuid = "11111111-2222-3333-4444-555555555555"
	shares := shareconfig.Config{Format: shareconfig.Format, SchemaVersion: 1, Revision: 1,
		Volumes: []shareconfig.Volume{{ID: "bulk", FilesystemUUID: uuid}}, Users: []shareconfig.User{}, Shares: []shareconfig.Share{}}
	nfs := nfsconfig.Policy{Format: nfsconfig.Format, SchemaVersion: 1, Revision: 1, VolumeRevision: 1,
		Exports: []nfsconfig.Export{{ID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", VolumeID: "bulk", RelativePath: "books",
			Clients: []nfsconfig.Client{{Network: network, Access: "rw", Squash: "all", AnonymousUID: 1000, AnonymousGID: 1000, Security: "sys"}}}}}
	plan, err := fileserviceplan.Build(fileservice.Config{Format: fileservice.ConfigFormat, SchemaVersion: 1, Revision: 1, Shares: shares, NFS: nfs}, 0,
		fileserviceplan.IdentitySnapshot{Complete: true, Generation: 1, Fingerprint: sha256.Sum256([]byte("disposable-nfs-input-fixture")), Registry: registry,
			UnixUIDs: []uint32{1000}, UnixGIDs: []uint32{1000}, Samba: []fileserviceplan.SambaIdentity{}},
		fileserviceplan.StorageSnapshot{Complete: true, Generation: 1, Volumes: []fileserviceplan.ObservedVolume{{VolumeID: "bulk", FilesystemUUID: uuid,
			MountPath: shareconfig.VolumeMountRoot + "/bulk", Compatibility: fileserviceplan.CompatibilityQualified, MountID: 73, DeviceMajor: 9, DeviceMinor: 1}}})
	if err != nil {
		return fileserviceplan.NFSv3Candidate{}, err
	}
	return plan.NFSv3TCPCandidate()
}

func stageNFSInputsQEMU(candidate fileserviceplan.NFSv3Candidate) error {
	documents, err := NFSFixtureConfigurationQEMU(candidate)
	if err != nil {
		return err
	}
	for _, path := range []string{nfsConfigViewQEMU, nfsStateViewQEMU} {
		if err := os.Mkdir(path, 0700); err != nil {
			return err // Fresh paths only, never adopt/clean existing state.
		}
	}
	const flags = unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC
	if err := unix.Mount("tmpfs", nfsConfigViewQEMU, "tmpfs", flags, "mode=0755,size=1m"); err != nil {
		return err
	}
	for name, data := range documents {
		mode := os.FileMode(0444)
		if name == "exports" {
			mode = 0400
		}
		if err := os.WriteFile(filepath.Join(nfsConfigViewQEMU, name), []byte(data), mode); err != nil {
			return err
		}
	}
	if err := unix.Mount("", nfsConfigViewQEMU, "", flags|unix.MS_REMOUNT|unix.MS_RDONLY, ""); err != nil {
		return err
	}
	if err := unix.Mount("tmpfs", nfsStateViewQEMU, "tmpfs", flags, "mode=0700,size=1m"); err != nil {
		return err
	}
	return os.Mkdir(filepath.Join(nfsStateViewQEMU, "nfs"), 0700)
}

func nfsInputCallerQEMU(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), "nfs-fixture-input-caller"), nil
}

// Owns only the fresh fixture caller supplied by its containing probe. This
// does not consume a retained root borrowed from another lifetime.
func probeNFSInputsQEMU(ctx context.Context, expected []byte, codeRoot *os.File) (result error) {
	phase := "stage"
	defer func() {
		if result != nil {
			nfsInputsProbeErrorQEMU = result // Keep ORIGINAL uncertain rollback.
			fmt.Fprintf(os.Stderr, "PHANTOWD_NFS_INPUTS_FAILURE phase=%s\n", phase)
		}
	}()
	candidate, err := nfsInputsFixtureCandidateQEMU("127.0.0.1/32")
	if err != nil || ctx == nil || nfsCodeGuardQEMU() != nil {
		return ErrInvalid
	}
	if err := stageNFSInputsQEMU(candidate); err != nil {
		return err
	}
	configuration, err := nfsInputCallerQEMU(nfsConfigViewQEMU)
	if err != nil {
		return err
	}
	state, err := nfsInputCallerQEMU(nfsStateViewQEMU)
	if err != nil {
		return err
	}
	before, err := retainedFixtureFDCount()
	if err != nil {
		return err
	}
	phase = "constructor-rollback"
	changed, err := nfsInputsFixtureCandidateQEMU("127.0.0.2/32")
	if err != nil {
		return err
	}
	value, err := NewNFSInputsQEMU(ctx, expected, changed, codeRoot, configuration, state)
	if value != nil || !errors.Is(err, ErrMismatch) || hasConstructionReview(err) {
		return errors.New("wrong-candidate rollback not verified")
	}
	if after, err := retainedFixtureFDCount(); err != nil || after != before {
		return errors.New("wrong-candidate rollback leaked inputs")
	}
	stray := filepath.Join(nfsStateViewQEMU, "nfs/stray")
	if err := os.WriteFile(stray, []byte("not-fresh"), 0600); err != nil {
		return err
	}
	value, err = NewNFSInputsQEMU(ctx, expected, candidate, codeRoot, configuration, state)
	if value != nil || !errors.Is(err, ErrMismatch) || hasConstructionReview(err) {
		return errors.New("nonfresh-state rollback not verified")
	}
	if after, err := retainedFixtureFDCount(); err != nil || after != before {
		return errors.New("nonfresh-state rollback leaked inputs")
	}
	if err := os.Remove(stray); err != nil {
		return err
	}
	phase = "normal-construction"
	good, err := NewNFSInputsQEMU(ctx, expected, candidate, codeRoot, configuration, state)
	if err != nil {
		return err
	}
	phase = "copied-handle"
	copyInputs := *good
	if copyInputs.Check(ctx) != ErrInvalid || copyInputs.Close() != ErrInvalid {
		return errors.New("copied input lifetime accepted")
	}
	phase = "pre-canceled-check"
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if !errors.Is(good.Check(canceled), context.Canceled) || good.Check(ctx) != nil {
		return errors.New("pre-cancellation changed input lifetime")
	}
	phase = "real-exportfs-table"
	if err := probeNFSTableQEMU(ctx, good, candidate); err != nil {
		return err
	}
	phase = "real-rpcbind-lifetime"
	if err := probeNFSRPCBindQEMU(ctx, good); err != nil {
		return err
	}
	phase = "mutable-file-write"
	etab := filepath.Join(nfsStateViewQEMU, "nfs/etab")
	temporary := etab + ".tmp"
	if err := os.WriteFile(etab, []byte("first"), 0600); err != nil {
		return err
	}
	if err := os.WriteFile(temporary, []byte("replacement"), 0600); err != nil {
		return err
	}
	phase = "mutable-file-rename"
	if err := os.Rename(temporary, etab); err != nil {
		return err
	}
	phase = "mutable-update-check"
	if err := good.Check(ctx); err != nil {
		return err
	}
	phase = "normal-close"
	if err := good.Close(); err != nil {
		return err
	}
	phase = "closed-repeat-check"
	if good.Close() != nil || good.Check(ctx) == nil {
		return errors.New("normal closure repeat or closed check failed")
	}
	phase = "normal-fd-balance"
	if after, err := retainedFixtureFDCount(); err != nil || after != before {
		return errors.New("normal input closure leaked references")
	}
	if err := os.Remove(etab); err != nil {
		return err
	}
	// Independent read-only collectors, not exclusive service admissions. Both
	// are captured while fresh; neither can release/settle the other's review.
	phase = "capture-original-review-inputs"
	first, err := NewNFSInputsQEMU(ctx, expected, candidate, codeRoot, configuration, state)
	if err != nil {
		return err
	}
	nfsInputsProbeRetainedQEMU = append(nfsInputsProbeRetainedQEMU, first)
	second, err := NewNFSInputsQEMU(ctx, expected, candidate, codeRoot, configuration, state)
	if err != nil {
		return err
	}
	nfsInputsProbeRetainedQEMU = append(nfsInputsProbeRetainedQEMU, second)
	if err := errors.Join(configuration.Close(), state.Close(), codeRoot.Close()); err != nil || first.Check(ctx) != nil || second.Check(ctx) != nil {
		return errors.New("caller closure lost original input references")
	}
	phase = "configuration-overmount"
	documents, _ := NFSFixtureConfigurationQEMU(candidate)
	const replacement = "/run/phantowd-nfs-input-config-replacement"
	if err := os.WriteFile(replacement, []byte(documents["exports"]), 0400); err != nil {
		return err
	}
	leaf := filepath.Join(nfsConfigViewQEMU, "exports")
	if err := unix.Mount(replacement, leaf, "", unix.MS_BIND, ""); err != nil {
		return err
	}
	if !errors.Is(first.Check(ctx), ErrReviewRequired) {
		return errors.New("byte-identical configuration overmount admitted")
	}
	if err := unix.Unmount(leaf, 0); err != nil {
		return err
	}
	if !errors.Is(first.Check(ctx), ErrReviewRequired) || !errors.Is(first.Close(), ErrReviewRequired) || second.Check(ctx) != nil {
		return errors.New("configuration review restored or other collector falsified")
	}
	phase = "state-directory-replacement"
	leaf = filepath.Join(nfsStateViewQEMU, "nfs")
	saved := filepath.Join(nfsStateViewQEMU, "nfs.original")
	if err := os.Rename(leaf, saved); err != nil {
		return err
	}
	if err := os.Mkdir(leaf, 0700); err != nil || !errors.Is(second.Check(ctx), ErrReviewRequired) {
		return errors.New("state-directory replacement admitted")
	}
	if err := os.Remove(leaf); err != nil {
		return err
	}
	if err := os.Rename(saved, leaf); err != nil {
		return err
	}
	retained, err := retainedFixtureFDCount()
	if err != nil || !errors.Is(second.Check(ctx), ErrReviewRequired) || !errors.Is(second.Close(), ErrReviewRequired) {
		return errors.New("state restoration erased review")
	}
	if after, err := retainedFixtureFDCount(); err != nil || after != retained || len(first.code.inner.state.files) != 2 || len(second.code.inner.state.files) != 2 {
		return errors.New("reviewed original inputs were released")
	}
	fmt.Println("PHANTOWD_NFS_INPUTS_READY same_candidate=true config_files=9 state_dirs=2 original_code=true caller_copies_closed=true normal_fd_balance=true wrong_candidate_refused=true nonfresh_refused=true mutable_updates=true config_overmount_review=true state_replacement_review=true restored_refused=true original_refs_retained=true service=false recovery=false scope=qemu-only")
	return nil
}
