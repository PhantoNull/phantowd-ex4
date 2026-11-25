// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicystore"
	"golang.org/x/sys/unix"
)

const (
	rc0StateName  = "rc0-state"
	rc0StateStage = ".rc0-state.provisioning"
)

// The caller authorizes first provisioning on an already selected local ext
// parent. The original operator policy copy remains outside this transaction.
func provisionInheritedRC0State(ctx context.Context, input io.Reader, installation, origin string) (result error) {
	if developmentBrowserEnrollment || os.Getuid() != 0 || os.Geteuid() != 0 {
		return errRC0Review
	}
	parent, err := takeStartupFile(3, unix.S_IFDIR)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, parent.Close()) }()
	policy, _, err := readRC0PolicyGrant(4)
	if err != nil || naspolicystore.ValidateInitial(installation, policy) != nil {
		return errRC0Review
	}
	tls, err := takeStartupFile(5, unix.S_IFREG)
	if err != nil {
		return err
	}
	bundle, _, err := readPrivateStartupFile(tls, 0, maxTLSIdentityBytes)
	defer clear(bundle)
	if errors.Join(err, tls.Close()) != nil || rc0TLSBundleFingerprint(bundle, origin, time.Now()) == "" {
		return errRC0Review
	}
	credentials, err := io.ReadAll(io.LimitReader(input, maxAdministratorProvisionInput+1))
	defer clear(credentials)
	if err != nil {
		return errRC0Review
	}
	if _, err := decodeAdministratorProvisioning(bytes.NewReader(credentials)); err != nil {
		return errRC0Review
	}
	uid, gid, err := managementAPIIdentity()
	if err != nil {
		return err
	}
	root, err := lockRC0StateRoot(parent)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, root.Close()) }()
	if ctx.Err() != nil || !rc0AbsentRole(root, rc0StateName) || !rc0AbsentRole(root, rc0StateStage) {
		return errRC0Review
	}
	fd := int(root.Fd())
	// Any interrupted stage is retained. The final name is published only
	// after the three original stores confirm provisioning and sync.
	if unix.Mkdirat(fd, rc0StateStage, 0700) != nil || unix.Fsync(fd) != nil {
		return errRC0Review
	}
	stage, err := openRC0Role(root, rc0StateStage, unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return err
	}
	err = stage.Chmod(0700)
	if err == nil {
		err = naspolicystore.ProvisionInitial(stage, installation, policy)
	}
	if err == nil {
		err = publishRC0TLS(stage, bundle, false)
	}
	if err == nil {
		err = provisionRC0StateAdministrator(ctx, stage, uid, gid, credentials)
	}
	if err == nil {
		err = stage.Sync()
	}
	if err := errors.Join(err, stage.Close(), ctx.Err()); err != nil {
		return err
	}
	if unix.Renameat2(fd, rc0StateStage, fd, rc0StateName, unix.RENAME_NOREPLACE) != nil || unix.Fsync(fd) != nil {
		return errRC0Review
	}
	return nil
}

func provisionRC0StateAdministrator(ctx context.Context, stage *os.File, uid, gid uint32, credentials []byte) (result error) {
	if ctx.Err() != nil || unix.Mkdirat(int(stage.Fd()), "accounts", 0700) != nil {
		return errRC0Review
	}
	accounts, err := openRC0Role(stage, "accounts", unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, accounts.Close()) }()
	if err := errors.Join(accounts.Chmod(0700), accounts.Chown(int(uid), int(gid))); err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, "/proc/self/exe", "--provision-administrator")
	cmd.Dir = "/"
	cmd.Env = []string{"LC_ALL=C"}
	cmd.ExtraFiles = []*os.File{accounts}
	cmd.Stdin = bytes.NewReader(credentials)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{}}}
	return cmd.Run()
}
