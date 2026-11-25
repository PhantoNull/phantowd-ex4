// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

var errRC0TLSProvision = errors.New("RC0 TLS identity was not confirmed")

func provisionInheritedRC0TLS(input io.Reader, origin, expected string) (result error) {
	if developmentBrowserEnrollment || os.Getuid() != 0 || os.Geteuid() != 0 {
		return errRC0TLSProvision
	}
	if expected != "" && !validRC0TLSFingerprint(expected) {
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
	if err != nil {
		return errRC0TLSProvision
	}
	fingerprint := rc0TLSBundleFingerprint(bundle, origin, time.Now())
	if fingerprint == "" || fingerprint == expected {
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
	if expected != "" {
		current, err := openRC0TLSIdentity(root)
		if err != nil {
			return errRC0TLSProvision
		}
		pair, err := readTLSIdentity(current, 0)
		if closeErr := current.Close(); err != nil || closeErr != nil ||
			tlsLeafFingerprint(pair.Certificate[0]) != expected {
			return errRC0TLSProvision
		}
	}
	return publishRC0TLS(root, bundle, expected != "")
}

func validRC0TLSFingerprint(text string) bool {
	if len(text) != sha256.Size*2 {
		return false
	}
	digest, err := hex.DecodeString(text)
	return err == nil && hex.EncodeToString(digest) == text
}

func tlsLeafFingerprint(der []byte) string {
	digest := sha256.Sum256(der)
	return hex.EncodeToString(digest[:])
}

func rc0TLSBundleFingerprint(bundle []byte, origin string, now time.Time) string {
	if len(bundle) == 0 || len(bundle) > maxTLSIdentityBytes {
		return ""
	}
	parsed, err := parseOrigin(origin)
	if err != nil || parsed.Scheme != "https" {
		return ""
	}
	pair, err := tls.X509KeyPair(bundle, bundle)
	if err != nil || validateTLSLeaf(&pair, parsed.Hostname(), now) != nil {
		return ""
	}
	for _, der := range pair.Certificate[1:] {
		if _, err := x509.ParseCertificate(der); err != nil {
			return ""
		}
	}
	return tlsLeafFingerprint(pair.Certificate[0])
}

// The retained state-root lock excludes the supervisor and other supported
// writers. Leave interrupted staging in place for explicit review.
func publishRC0TLS(root *os.File, bundle []byte, replace bool) error {
	if !rc0AbsentRole(root, rc0TLSStage) || !replace && !rc0AbsentRole(root, rc0TLSIdentity) {
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
	flags := uint(unix.RENAME_NOREPLACE)
	if replace {
		flags = 0
	}
	if unix.Renameat2(dir, rc0TLSStage, dir, rc0TLSIdentity, flags) != nil ||
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
