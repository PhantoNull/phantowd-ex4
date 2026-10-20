//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"golang.org/x/sys/unix"
)

// NFSInputsQEMU is a disposable input lifetime, not a daemon/kernel Owner or
// product activation/persistence authority. Only the original handle is valid.
type NFSInputsQEMU struct {
	original *NFSInputsQEMU
	code     *NFSCodeQEMU
}

const (
	nfsConfigViewQEMU = "/run/phantowd-nfs-input-configuration"
	nfsStateViewQEMU  = "/run/phantowd-nfs-input-state"
)

// All inputs are fixed at construction; no operation accepts a new candidate,
// path, backend or identity. Failed uncertain rollback must remain retained in
// its ORIGINAL error chain. A private finite QEMU table-listing probe may borrow
// these originals only while holding the code gate through verified settlement.
func NewNFSInputsQEMU(ctx context.Context, expected []byte, candidate fileserviceplan.NFSv3Candidate, codeRoot, configRoot, stateRoot *os.File) (_ *NFSInputsQEMU, result error) {
	if ctx == nil || codeRoot == nil || configRoot == nil || stateRoot == nil {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	plan, err := nfsConfigurationPlanQEMU(candidate)
	if err != nil {
		return nil, err
	}
	code, err := NewNFSCodeQEMU(ctx, expected, codeRoot)
	if err != nil {
		return nil, err
	}
	s, err := code.enter(ctx)
	if err != nil {
		return nil, constructionRollback(err, code.inner, code.inner.releaseUnstarted)
	}
	defer s.leave()
	defer func() {
		if result != nil {
			result = constructionRollback(result, s, s.releaseUnstarted)
		}
	}()
	if err := s.revalidate(ctx); err != nil {
		return nil, err
	}
	s.configuration, err = plan.retain(ctx, configRoot)
	if err != nil {
		return nil, err
	}
	s.state, err = retainNFSStateQEMU(ctx, stateRoot)
	if err != nil {
		return nil, err
	}
	if err := s.revalidate(ctx); err != nil {
		return nil, err
	}
	o := &NFSInputsQEMU{code: code}
	o.original = o
	return o, nil
}

func nfsConfigurationPlanQEMU(candidate fileserviceplan.NFSv3Candidate) (*configurationPlan, error) {
	documents, err := NFSFixtureConfigurationQEMU(candidate)
	if err != nil {
		return nil, err
	}
	files := make([]File, 0, len(documents))
	for name, data := range documents {
		mode := uint32(0444)
		if name == "exports" {
			mode = 0400
		}
		files = append(files, File{Path: name, SHA256: sha256.Sum256([]byte(data)), Size: int64(len(data)), Mode: mode})
	}
	return newConfigurationPlan(files)
}

func nfsInputNamedRootQEMU(path string, inode, mount uint64, major, minor uint32) error {
	var st unix.Statx_t
	const mask = unix.STATX_BASIC_STATS | unix.STATX_MNT_ID_UNIQUE
	if unix.Statx(unix.AT_FDCWD, path, unix.AT_SYMLINK_NOFOLLOW|unix.AT_NO_AUTOMOUNT, mask, &st) != nil || st.Mask&mask != mask ||
		st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Ino != inode || st.Mnt_id != mount || st.Dev_major != major || st.Dev_minor != minor {
		return ErrMismatch
	}
	return nil
}

func (o *NFSInputsQEMU) valid() bool { return o != nil && o.original == o && o.code != nil }
func (o *NFSInputsQEMU) Check(ctx context.Context) error {
	if !o.valid() {
		return ErrInvalid
	}
	return o.code.Check(ctx)
}
func (o *NFSInputsQEMU) Close() error {
	if !o.valid() {
		return ErrInvalid
	}
	return o.code.Close()
}
func (NFSInputsQEMU) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
func (*NFSInputsQEMU) UnmarshalJSON([]byte) error  { return ErrInvalid }
func (NFSInputsQEMU) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "nfs-inputs{private}")
}
