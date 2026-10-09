//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"crypto/sha256"
	"debug/elf"
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

const pendingClientProgramQEMU = "fixture/pending-write"
const pendingClientBootstrapQEMU = "fixture/launcher"

// PendingClientDocumentsQEMU returns fixed, non-secret client-root inputs for
// trusted fixture construction. These bytes do not authorize an image/runtime.
// No identities, services, paths, credentials or policy come from a caller.
func PendingClientDocumentsQEMU() map[string]string {
	return map[string]string{
		"sys/firmware/devicetree/base/model": "ARM Versatile PB\x00",
		"etc/passwd":                         "nobody:!:65534:65534:nobody:/:/sbin/nologin\n",
		"etc/group":                          "nobody:!:65534:\n",
		"etc/nsswitch.conf":                  "passwd: files\ngroup: files\nhosts: files\n",
		"etc/hosts":                          "127.0.0.1 localhost\n",
		"etc/samba/smb.conf": "[global]\n" +
			"client min protocol = SMB3_11\nclient max protocol = SMB3_11\n" +
			"client signing = mandatory\nclient ipc signing = mandatory\nname resolve order = host\n",
	}
}

func pendingClientPlansQEMU(client, bootstrap *Plan) error {
	if client == nil || bootstrap == nil || len(bootstrap.files) != 1 || len(bootstrap.aliases) != 0 ||
		bootstrap.files[0].Path != pendingClientBootstrapQEMU || bootstrap.files[0].Mode != 0555 {
		return ErrInvalid
	}
	files := make(map[string]File, len(client.files))
	for _, file := range client.files {
		files[file.Path] = file
	}
	program, exists := files[pendingClientProgramQEMU]
	if !exists || program.Mode != 0555 || program.Size > 1<<20 {
		return ErrInvalid
	}
	for name, bytes := range PendingClientDocumentsQEMU() {
		file, exists := files[name]
		if !exists || file.Mode != 0444 || file.Size != int64(len(bytes)) || file.SHA256 != sha256.Sum256([]byte(bytes)) {
			return ErrMismatch
		}
	}
	for _, binding := range []string{"lib/ld-linux.so.3", "usr/lib/libsmbclient.so.0"} {
		file, exists := files[binding]
		if !exists {
			for _, alias := range client.aliases {
				if alias.Path == binding {
					file, exists = files[alias.Target]
					break
				}
			}
		}
		if !exists || file.Mode != 0555 {
			return ErrMismatch
		}
	}
	return nil
}

// Separate private retention primitive, NOT a process Owner/admission token.
// Its containing lifecycle owner must serialize all access, recheck after
// fixing its other inputs, and prove group settlement before calling release.
// Do not pass its private descriptors to a consumer or operate on aliases.
type pendingClientInputsQEMU struct {
	client, bootstrap *retainedCode
	releaseErr        error
}

func newPendingClientInputsQEMU(ctx context.Context, clientPlan, bootstrapPlan *Plan, clientRoot, bootstrapRoot *os.File) (inputs *pendingClientInputsQEMU, result error) {
	if ctx == nil || clientRoot == nil || bootstrapRoot == nil {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := pendingClientPlansQEMU(clientPlan, bootstrapPlan); err != nil {
		return nil, err
	}
	if err := sambaCodeFixtureGuard(); err != nil {
		return nil, err
	}
	i := &pendingClientInputsQEMU{}
	defer func() {
		if result != nil {
			result = errors.Join(result, i.release())
		}
	}()
	var err error
	i.client, err = clientPlan.prepareRetainedCode(ctx, clientRoot)
	if err != nil {
		return nil, err
	}
	i.bootstrap, err = bootstrapPlan.prepareRetainedCode(ctx, bootstrapRoot)
	if err != nil {
		return nil, err
	}
	if err := i.revalidate(ctx); err != nil {
		return nil, err
	}
	return i, nil
}

func pendingRootShapeQEMU(code *retainedCode) error {
	if code == nil || code.root == nil {
		return ErrUnavailable
	}
	var fs unix.Statfs_t
	var root unix.Statx_t
	if unix.Fstatfs(int(code.root.Fd()), &fs) != nil ||
		fs.Type != unix.TMPFS_MAGIC ||
		fs.Flags&(unix.ST_RDONLY|unix.ST_NOSUID|unix.ST_NODEV|unix.ST_NOEXEC) != unix.ST_RDONLY|unix.ST_NOSUID|unix.ST_NODEV ||
		unix.Statx(int(code.root.Fd()), "", unix.AT_EMPTY_PATH|unix.AT_NO_AUTOMOUNT, unix.STATX_BASIC_STATS, &root) != nil ||
		root.Mode != unix.S_IFDIR|0755 || root.Uid != 0 || root.Gid != 0 ||
		root.Attributes_mask&unix.STATX_ATTR_MOUNT_ROOT == 0 || root.Attributes&unix.STATX_ATTR_MOUNT_ROOT == 0 {
		return ErrMismatch
	}
	return nil
}

func (i *pendingClientInputsQEMU) revalidate(ctx context.Context) error {
	if i == nil || i.client == nil || i.bootstrap == nil || i.releaseErr != nil || ctx == nil {
		return ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, code := range []*retainedCode{i.client, i.bootstrap} {
		if err := code.revalidate(ctx); err != nil {
			return err
		}
		if err := pendingRootShapeQEMU(code); err != nil {
			return err
		}
	}
	if i.client.metadata["."].Mnt_id == i.bootstrap.metadata["."].Mnt_id {
		return ErrMismatch
	}
	client, helper := i.client.files[pendingClientProgramQEMU], i.bootstrap.files[pendingClientBootstrapQEMU]
	if client == nil || helper == nil || staticExecutable(helper) != nil {
		return ErrMismatch
	}
	bootstrap, err := elf.NewFile(helper)
	if err != nil || bootstrap.Class != elf.ELFCLASS32 || bootstrap.Data != elf.ELFDATA2LSB || bootstrap.Machine != elf.EM_ARM {
		return ErrMismatch
	}
	program, err := elf.NewFile(client)
	if err != nil || program.Class != elf.ELFCLASS32 || program.Data != elf.ELFDATA2LSB ||
		program.Machine != elf.EM_ARM || program.Type != elf.ET_DYN {
		return ErrMismatch
	}
	// ReadAt/ELF inspection does not consume the original executable offset.
	interpreters := 0
	for _, segment := range program.Progs {
		if segment.Type == elf.PT_INTERP {
			bytes := make([]byte, len("/lib/ld-linux.so.3\x00")+1)
			count, _ := segment.ReadAt(bytes, 0)
			if segment.Filesz != uint64(len("/lib/ld-linux.so.3\x00")) || string(bytes[:count]) != "/lib/ld-linux.so.3\x00" {
				return ErrMismatch
			}
			interpreters++
		}
	}
	needed, err := program.DynString(elf.DT_NEEDED)
	if err != nil || interpreters != 1 {
		return ErrMismatch
	}
	found := false
	for _, name := range needed {
		if name == "libsmbclient.so.0" {
			found = true
		}
	}
	if !found {
		return ErrMismatch
	}
	return ctx.Err()
}

// This releases no processes and is private to trusted containing composition.
// A close error is sticky; unattempted originals remain retained, never retried.
func (i *pendingClientInputsQEMU) release() error {
	if i == nil {
		return nil
	}
	if i.releaseErr != nil {
		return i.releaseErr
	}
	for _, code := range []*retainedCode{i.client, i.bootstrap} {
		if err := code.release(); err != nil {
			i.releaseErr = err
			return err
		}
	}
	return nil
}

// ProbePendingClientInputsQEMU exercises admission/retention only in a guarded
// disposable guest, without process launch, secret input or service activation.
// Expected Plans come from separate fixture build inputs, never from the roots
// being inspected. It returns no references or execution authority.
func (p *Plan) ProbePendingClientInputsQEMU(ctx context.Context, bootstrap *Plan, clientRoot, bootstrapRoot *os.File) (result error) {
	if err := sambaCodeFixtureGuard(); err != nil {
		return err
	}
	before, err := retainedFixtureFDCount()
	if err != nil {
		return err
	}
	// Exercise complete expected-byte mismatch and partial constructor cleanup.
	for _, role := range []int{0, 1} {
		candidate := p
		if role == 1 {
			candidate = bootstrap
		}
		if candidate == nil || len(candidate.files) == 0 {
			return ErrInvalid
		}
		files := append([]File(nil), candidate.files...)
		for index := range files {
			if files[index].Path == pendingClientProgramQEMU || files[index].Path == pendingClientBootstrapQEMU {
				files[index].SHA256[0] ^= 1
			}
		}
		wrong, err := NewPlan(files, candidate.aliases)
		if err != nil {
			return err
		}
		clientPlan, helperPlan := p, bootstrap
		if role == 0 {
			clientPlan = wrong
		} else {
			helperPlan = wrong
		}
		value, err := newPendingClientInputsQEMU(ctx, clientPlan, helperPlan, clientRoot, bootstrapRoot)
		if value != nil || !errors.Is(err, ErrMismatch) {
			return ErrMismatch
		}
	}
	caller, err := duplicateRoot(clientRoot)
	if err != nil {
		return err
	}
	helperCaller, err := duplicateRoot(bootstrapRoot)
	if err != nil {
		return errors.Join(err, caller.Close())
	}
	value, err := newPendingClientInputsQEMU(ctx, p, bootstrap, caller, helperCaller)
	callerErr := errors.Join(caller.Close(), helperCaller.Close())
	if err != nil || callerErr != nil {
		return errors.Join(err, callerErr, value.release())
	}
	defer func() { result = errors.Join(result, value.release()) }()
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if !errors.Is(value.revalidate(canceled), context.Canceled) {
		return ErrMismatch
	}
	if err := value.revalidate(ctx); err != nil {
		return err
	}
	if err := value.release(); err != nil {
		return err
	}
	if value.revalidate(ctx) == nil {
		return ErrMismatch
	}
	after, err := retainedFixtureFDCount()
	if err != nil || before != after {
		return errors.Join(ErrMismatch, err)
	}
	fmt.Println("PHANTOWD_PENDING_INPUTS_READY complete_root=true complete_bootstrap=true fixed_documents=true original_pins=true caller_duplicate_closed=true late_rechecked=true mismatches=2 canceled_refused=true released_refused=true no_fd_leak=true execution=false scope=qemu-only")
	return nil
}
