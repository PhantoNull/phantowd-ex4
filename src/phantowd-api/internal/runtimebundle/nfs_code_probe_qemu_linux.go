//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// Fixed disposable probe keeps reviewed authority until its process exits.
// This is not a product quarantine, recovered instance or release protocol.
var nfsCodeProbeRetainedQEMU *NFSCodeQEMU

// ProbeNFSCodeQEMU stages public guest code into its own bounded RAM mount.
// Only the loader's fixed --list mode executes; no daemon entrypoint or data
// device opens. The separate static child is non-root/capability-free.
func ProbeNFSCodeQEMU(ctx context.Context, expected []byte) (result error) {
	phase := "guard"
	defer func() {
		if result != nil {
			fmt.Fprintf(os.Stderr, "PHANTOWD_NFS_CODE_FAILURE phase=%s\n", phase)
		}
	}()
	if ctx == nil || nfsCodeGuardQEMU() != nil {
		return ErrInvalid
	}
	plan, err := NFSExpectedPlanQEMU(expected)
	if err != nil || plan.bytes > 8<<20 {
		return ErrInvalid
	}
	phase = "stage"
	if err := stageNFSCodeQEMU(ctx, plan); err != nil {
		return err
	}
	openRoot := func() (*os.File, error) {
		fd, err := unix.Open(nfsCodeViewQEMU, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, err
		}
		return os.NewFile(uintptr(fd), "nfs-code-fixture-caller"), nil
	}
	caller, err := openRoot()
	if err != nil {
		return err
	}
	before, err := retainedFixtureFDCount()
	if err != nil {
		return err
	}
	// Wrong expected bytes must roll back the independently acquired namespace
	// and original code root without consuming the caller's descriptor.
	phase = "wrong-hash-rollback"
	wrong := bytes.Replace(expected, []byte(hex.EncodeToString(plan.files[0].SHA256[:])), []byte("1111111111111111111111111111111111111111111111111111111111111111"), 1)
	if code, err := NewNFSCodeQEMU(ctx, wrong, caller); code != nil || !errors.Is(err, ErrMismatch) || hasConstructionReview(err) {
		return errors.New("NFS code mismatch rollback not verified")
	}
	if after, err := retainedFixtureFDCount(); err != nil || after != before {
		return errors.New("NFS code mismatch leaked references")
	}
	phase = "normal-lifetime"
	code, err := NewNFSCodeQEMU(ctx, expected, caller)
	if err != nil {
		return err
	}
	if err := caller.Close(); err != nil || code.Check(ctx) != nil {
		return errors.New("NFS caller closure invalidated retained code")
	}
	phase = "isolated-loader"
	if err := probeNFSLoaderQEMU(ctx, code); err != nil {
		return err
	}
	copyCode := *code
	if copyCode.Check(ctx) != ErrInvalid || copyCode.Close() != ErrInvalid {
		return errors.New("NFS copied code lifetime accepted")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if !errors.Is(code.Check(canceled), context.Canceled) || code.Check(ctx) != nil || code.Close() != nil || code.Close() != nil || code.Check(ctx) == nil {
		return errors.New("NFS code cancellation/normal closure failed")
	}
	if after, err := retainedFixtureFDCount(); err != nil || after != before-1 {
		return errors.New("NFS normal code closure leaked references")
	}
	// Hash-correct but non-ELF negative fixture proves headers are checked from
	// the actual held files, not inferred from metadata claims. No consumer exists.
	const program = "usr/sbin/rpcbind"
	phase = "non-elf-rollback"
	badBytes := bytes.Repeat([]byte{0x41}, 32)
	if err := remountNFSCodeQEMU(false); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(nfsCodeViewQEMU, program), badBytes, 0555); err != nil {
		return err
	}
	if err := remountNFSCodeQEMU(true); err != nil {
		return err
	}
	badExpected, err := corruptNFSExpectedQEMU(expected, program, badBytes)
	if err != nil {
		return err
	}
	caller, err = openRoot()
	if err != nil {
		return err
	}
	before, _ = retainedFixtureFDCount()
	if value, err := NewNFSCodeQEMU(ctx, badExpected, caller); value != nil || !errors.Is(err, ErrMismatch) || hasConstructionReview(err) {
		return errors.New("NFS hash-correct non-ELF code was admitted")
	}
	if after, err := retainedFixtureFDCount(); err != nil || after != before {
		return errors.New("NFS complete-input constructor rollback leaked")
	}
	if err := remountNFSCodeQEMU(false); err != nil {
		return err
	}
	if err := copyNFSGuestObjectQEMU(ctx, plan, program, false); err != nil {
		return err
	}
	if err := remountNFSCodeQEMU(true); err != nil {
		return err
	}
	phase = "restored-construction"
	code, err = NewNFSCodeQEMU(ctx, expected, caller)
	if err != nil {
		return err
	}
	if err := caller.Close(); err != nil {
		return err
	}
	nfsCodeProbeRetainedQEMU = code
	phase = "same-bytes-overmount"
	const replacement = "/run/phantowd-nfs-code-replacement"
	file, err := os.OpenFile(replacement, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0555)
	if err != nil {
		return err
	}
	pin := code.inner.code.files[program]
	stat, err := pin.Stat()
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(file, io.NewSectionReader(pin, 0, stat.Size()))
	if err := errors.Join(copyErr, file.Close()); err != nil {
		return err
	}
	leaf := filepath.Join(nfsCodeViewQEMU, program)
	if err := unix.Mount(replacement, leaf, "", unix.MS_BIND, ""); err != nil {
		return err
	}
	if !errors.Is(code.Check(ctx), ErrReviewRequired) {
		return errors.New("NFS byte-identical code overmount was admitted")
	}
	retained, err := retainedFixtureFDCount()
	if err != nil || len(code.inner.code.files) != len(plan.files) || code.inner.namespace == nil {
		return errors.New("NFS reviewed code references were lost")
	}
	phase = "retained-review"
	if err := unix.Unmount(leaf, 0); err != nil {
		return err
	}
	if !errors.Is(code.Check(ctx), ErrReviewRequired) || !errors.Is(code.Close(), ErrReviewRequired) {
		return errors.New("NFS code restoration erased review")
	}
	if after, err := retainedFixtureFDCount(); err != nil || after != retained {
		return errors.New("NFS reviewed code operations released references")
	}
	fmt.Printf("PHANTOWD_NFS_CODE_COUNTS files=%d aliases=%d bytes=%d\n", len(plan.files), len(plan.aliases), plan.bytes)
	fmt.Println("PHANTOWD_NFS_CODE_READY original_pins=true namespace_bound=true caller_copy_closed=true normal_fd_balance=true constructor_rollback=true non_elf_refused=true same_bytes_overmount_refused=true restored_refused=true review_retained=true execution=loader-list-only scope=code-retention-and-loader-list")
	return nil
}

func remountNFSCodeQEMU(readOnly bool) error {
	flags := uintptr(unix.MS_REMOUNT | unix.MS_NOSUID | unix.MS_NODEV)
	if readOnly {
		flags |= unix.MS_RDONLY
	}
	return unix.Mount("", nfsCodeViewQEMU, "", flags, "")
}

func stageNFSCodeQEMU(ctx context.Context, plan *Plan) error {
	if err := os.Mkdir(nfsCodeViewQEMU, 0755); err != nil {
		return err // Fresh exact path only; no adoption/removal.
	}
	if err := unix.Mount("tmpfs", nfsCodeViewQEMU, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=0755,size=16m"); err != nil {
		return err
	}
	for _, file := range plan.files {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(nfsCodeViewQEMU, file.Path)), 0755); err != nil {
			return err
		}
		if err := copyNFSGuestObjectQEMU(ctx, plan, file.Path, true); err != nil {
			return err
		}
	}
	for _, alias := range plan.aliases {
		name := filepath.Join(nfsCodeViewQEMU, alias.Path)
		if err := os.MkdirAll(filepath.Dir(name), 0755); err != nil {
			return err
		}
		if err := os.Symlink("/"+alias.Target, name); err != nil {
			return err
		}
	}
	return remountNFSCodeQEMU(true)
}

func copyNFSGuestObjectQEMU(ctx context.Context, plan *Plan, name string, exclusive bool) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var expected File
	for _, file := range plan.files {
		if file.Path == name {
			expected = file
			break
		}
	}
	if expected.Path == "" {
		return ErrInvalid
	}
	base, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	fd, openErr := openBeneath(base, name, unix.O_RDONLY)
	closeErr := unix.Close(base)
	if openErr != nil || closeErr != nil {
		return errors.Join(openErr, closeErr)
	}
	source := os.NewFile(uintptr(fd), "nfs-public-guest-code")
	defer source.Close()
	flags := os.O_WRONLY | os.O_TRUNC
	if exclusive {
		flags = os.O_WRONLY | os.O_CREATE | os.O_EXCL
	}
	target, err := os.OpenFile(filepath.Join(nfsCodeViewQEMU, name), flags, 0555)
	if err != nil {
		return err
	}
	hash := sha256.New()
	count, copyErr := io.Copy(io.MultiWriter(target, hash), io.LimitReader(source, expected.Size+1))
	closeErr = target.Close()
	if copyErr != nil || closeErr != nil || count != expected.Size || !bytes.Equal(hash.Sum(nil), expected.SHA256[:]) {
		return ErrMismatch
	}
	return ctx.Err()
}

func corruptNFSExpectedQEMU(original []byte, program string, value []byte) ([]byte, error) {
	var document map[string]any
	if json.Unmarshal(original, &document) != nil {
		return nil, ErrInvalid
	}
	for _, entry := range document["objects"].([]any) {
		object := entry.(map[string]any)
		if object["path"] == program {
			document["total_bytes"] = document["total_bytes"].(float64) - object["size"].(float64) + float64(len(value))
			digest := sha256.Sum256(value)
			object["sha256"], object["size"] = hex.EncodeToString(digest[:]), len(value)
			return json.Marshal(document)
		}
	}
	return nil, ErrInvalid
}
