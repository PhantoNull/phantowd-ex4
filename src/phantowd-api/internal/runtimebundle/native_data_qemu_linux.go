//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strconv"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"golang.org/x/sys/unix"
)

// Fixed qualification documents, not desired policy or an activation plan.
// A complete Plan/storage/identity coordinator must replace this fixture before
// product sharing. Credential/authentication documents remain unchanged.
func SambaNativeDataDocumentsQEMU(lookup fileserviceplan.SambaEnrollmentLookup) (map[string]string, error) {
	documents, err := SambaCredentialDocumentsQEMU(lookup)
	if err != nil {
		return nil, err
	}
	documents["samba/smb.conf"] += "\n[readonly]\npath = /shares/readonly\nvalid users = qpsecond\nread list = qpsecond\nread only = yes\nguest ok = no\nwide links = no\nfollow symlinks = no\n\n[writable]\npath = /shares/writable\nvalid users = qpsecond\nwrite list = qpsecond\nread only = yes\nguest ok = no\nwide links = no\nfollow symlinks = no\n"
	return documents, nil
}

// ProbeNativeDataDescriptorQEMU runs one distinct, fixed data profile on a fresh
// runtime with qualified original code/config/state. The caller supplies only
// its two synthetic RO/RW mount roots and keeps them through verified closure.
// No identity Owner lease/complete mounted roster or product service is claimed.
func (p *Plan) ProbeNativeDataDescriptorQEMU(ctx context.Context, code, configuration, state *os.File, lookup fileserviceplan.SambaEnrollmentLookup, roots [2]*os.File) (result error) {
	r, err := p.newNativeSambaRuntimeQEMU(ctx, code, configuration, state, lookup, &roots)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, r.Close(context.Background())) }()
	// The peer was explicitly enrolled/enabled by the preceding actual native
	// credential campaign. No synthetic passdb entry or automatic enable here.
	const auth = "/run/native-qpsecond-good.auth"
	file, err := os.OpenFile(auth, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	r.authPaths = append(r.authPaths, auth)
	_, err = file.WriteString("username = qpsecond\npassword = native-qemu-only-password-29\n")
	if err := errors.Join(err, file.Close()); err != nil {
		return err
	}
	r.daemonAttempted = true
	observed, err := r.owner.Start(ctx)
	if err != nil || observed.State != processowner.StateReady || len(observed.Processes.Members) != 1 {
		return errors.Join(errors.New("native data daemon readiness"), err)
	}
	r.daemonPID = observed.Processes.Members[0].Process.PID
	if err := r.verifyNativeDaemonQEMU(ctx, r.daemonPID); err != nil {
		return err
	}
	base := "/proc/" + strconv.Itoa(r.daemonPID) + "/root/shares/"
	for index, name := range []string{"readonly", "writable"} {
		original, err := roots[index].Stat()
		actual, actualErr := os.Stat(base + name)
		var fs unix.Statfs_t
		if err != nil || actualErr != nil || !os.SameFile(original, actual) || unix.Statfs(base+name, &fs) != nil ||
			(fs.Flags&unix.ST_RDONLY != 0) != (index == 0) {
			return errors.New("native data view lost original object or RO role")
		}
	}
	for _, operation := range []string{"rw-write", "rw-read", "ro-read", "ro-write", "escape"} {
		if err := r.nativeDataClientQEMU(ctx, operation); err != nil {
			return err
		}
		if err := r.verifyNativeDaemonQEMU(ctx, r.daemonPID); err != nil {
			return err
		}
	}
	var created unix.Stat_t
	if unix.Fstatat(int(roots[1].Fd()), "created", &created, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		created.Mode&unix.S_IFMT != unix.S_IFREG || created.Uid != 2001 || created.Gid != 2001 || created.Size != 22 {
		return errors.New("native SMB write lost effective peer identity")
	}
	fd, writeErr := unix.Openat(int(roots[0].Fd()), "kernel-ro-proof", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC, 0600)
	if fd >= 0 {
		_ = unix.Close(fd)
	}
	if !errors.Is(writeErr, unix.EROFS) {
		return errors.New("native share read-only mount not kernel-enforced")
	}
	for _, path := range []string{"/run/native-share-download-rw", "/run/native-share-download-ro"} {
		contents, err := os.ReadFile(path)
		if err != nil || string(contents) != "native-share-qualified" {
			return errors.New("native SMB transfer contents mismatch")
		}
	}
	for _, path := range []string{"/run/native-share-download-escape", base + "readonly/forbidden"} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return errors.New("native SMB denial created an unintended file")
		}
	}
	return r.Close(context.Background()) // Whole daemon/clients settle before original roots release.
}

func (r *NativeSambaRuntimeQEMU) nativeDataClientQEMU(ctx context.Context, operation string) error {
	input, err := sealedNativeCredentialInputQEMU(nil)
	if err != nil {
		return err
	}
	args := []string{"native-data-client", operation}
	if operation == "ungranted" {
		args = []string{"native-ungranted-client"} // Fixed enabled/non-granted peer.
	}
	capture, err := processowner.NewCapture(processowner.CaptureSpec{
		ExecutableLabel: sambaFixtureHelper, Args: args,
		RunAs: &processowner.Credentials{UID: 0, GID: 0}, Timeout: 4 * time.Second, StopTimeout: time.Second,
	}, r.helper, input)
	err = errors.Join(err, input.Close())
	if err != nil {
		if capture != nil {
			err = errors.Join(err, capture.Close(context.Background()))
		}
		return err
	}
	r.pending = capture
	observed, runErr := capture.Capture(ctx)
	defer clear(observed.Stdout)
	defer clear(observed.Stderr)
	settled, settleErr := capture.Settled(context.Background())
	closeErr := capture.Close(context.Background())
	if !settled || settleErr != nil || closeErr != nil {
		r.owner.review = true
		return ErrReviewRequired
	}
	r.pending = nil
	if runErr != nil || observed.Kind != processowner.CaptureExited {
		return errors.Join(ErrReviewRequired, runErr)
	}
	output := append(observed.Stdout, observed.Stderr...)
	defer clear(output)
	if operation == "ungranted" {
		// ACCOUNT_DISABLED, timeout, signals and a launcher error are not grant
		// enforcement. The complete authority independently confirms enabled.
		if observed.ExitCode == 1 && bytes.Contains(output, []byte("NT_STATUS_LOGON_FAILURE")) &&
			!bytes.Contains(output, []byte("NT_STATUS_ACCOUNT_DISABLED")) {
			return nil
		}
	} else if operation == "ro-write" || operation == "escape" {
		if observed.ExitCode == 1 && (bytes.Contains(output, []byte("NT_STATUS_ACCESS_DENIED")) ||
			(operation == "escape" && (bytes.Contains(output, []byte("NT_STATUS_OBJECT_NAME_NOT_FOUND")) ||
				bytes.Contains(output, []byte("NT_STATUS_STOPPED_ON_SYMLINK"))))) {
			return nil
		}
	} else if observed.ExitCode == 0 && !bytes.Contains(output, []byte("NT_STATUS_")) {
		return nil
	}
	return errors.New("native SMB data operation or denial mismatch")
}
