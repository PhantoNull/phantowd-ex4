// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

var errRC0TLSProvision = errors.New("initial RC0 TLS identity could not be installed")

func provisionInheritedRC0TLS(input io.Reader, origin string) (result error) {
	if developmentBrowserEnrollment || os.Getuid() != 0 || os.Geteuid() != 0 {
		return errRC0TLSProvision
	}
	state, err := takeStartupFile(3, unix.S_IFDIR)
	if err != nil {
		return errRC0TLSProvision
	}
	defer func() {
		if state.Close() != nil {
			result = errRC0TLSProvision
		}
	}()
	bundle, err := io.ReadAll(io.LimitReader(input, maxTLSIdentityBytes+1))
	defer clear(bundle)
	if err != nil || !validRC0TLSBundle(bundle, origin, time.Now()) {
		return errRC0TLSProvision
	}
	root, err := lockRC0StateRoot(state)
	if err != nil {
		return errRC0TLSProvision
	}
	defer func() {
		if root.Close() != nil {
			result = errRC0TLSProvision
		}
	}()
	return publishInitialRC0TLS(root, bundle)
}

func validRC0TLSBundle(bundle []byte, origin string, now time.Time) bool {
	if len(bundle) == 0 || len(bundle) > maxTLSIdentityBytes {
		return false
	}
	parsed, err := parseOrigin(origin)
	if err != nil || parsed.Scheme != "https" {
		return false
	}
	pair, err := tls.X509KeyPair(bundle, bundle)
	if err != nil || validateTLSLeaf(&pair, parsed.Hostname(), now) != nil {
		return false
	}
	for _, der := range pair.Certificate[1:] {
		if _, err := x509.ParseCertificate(der); err != nil {
			return false
		}
	}
	return true
}

// The retained state-root lock excludes the supervisor and other supported
// writers. Leave interrupted staging in place for explicit review.
func publishInitialRC0TLS(root *os.File, bundle []byte) error {
	if !rc0AbsentRole(root, rc0TLSIdentity) || !rc0AbsentRole(root, rc0TLSStage) {
		return errRC0TLSProvision
	}
	stage, err := openRC0Role(root, rc0TLSStage, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL)
	if err != nil {
		return errRC0TLSProvision
	}
	dir := int(root.Fd())
	err = stage.Chmod(0600)
	if err == nil {
		err = unix.Fsync(dir)
	}
	if err == nil {
		_, err = stage.Write(bundle)
	}
	if err == nil {
		err = stage.Sync()
	}
	if closeErr := stage.Close(); err != nil || closeErr != nil {
		return errRC0TLSProvision
	}
	if unix.Renameat2(dir, rc0TLSStage, dir, rc0TLSIdentity, unix.RENAME_NOREPLACE) != nil ||
		unix.Fsync(dir) != nil {
		return errRC0TLSProvision
	}
	return nil
}

func rc0AbsentRole(root *os.File, name string) bool {
	var info unix.Stat_t
	err := unix.Fstatat(int(root.Fd()), name, &info, unix.AT_SYMLINK_NOFOLLOW|unix.AT_NO_AUTOMOUNT)
	return errors.Is(err, unix.ENOENT)
}
