// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"crypto/tls"
	"errors"
	"io"
	"os"
	"runtime"
)

const (
	maxTLSCertificatePEMBytes int64 = 256 << 10
	maxTLSPrivateKeyPEMBytes  int64 = 64 << 10
)

var errTLSMaterial = errors.New("TLS material is unavailable, unsafe or exceeds its size limit")

// Startup snapshot only: no issuer, parent-directory authority, rotation or
// durable trust policy is established by reading a supplied certificate pair.
func loadBoundedTLSKeyPair(certPath, keyPath string) (tls.Certificate, error) {
	certificate, err := readTLSMaterial(certPath, maxTLSCertificatePEMBytes, false)
	if err != nil {
		return tls.Certificate{}, errTLSMaterial
	}
	defer clear(certificate)
	key, err := readTLSMaterial(keyPath, maxTLSPrivateKeyPEMBytes, true)
	if err != nil {
		return tls.Certificate{}, errTLSMaterial
	}
	defer clear(key) // Only the owned raw PEM; parsed private-key memory remains.
	pair, err := tls.X509KeyPair(certificate, key)
	if err != nil {
		return tls.Certificate{}, errTLSMaterial
	}
	return pair, nil
}

func readTLSMaterial(path string, limit int64, private bool) (contents []byte, result error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > limit ||
		private && runtime.GOOS != "windows" && before.Mode().Perm()&0077 != 0 {
		return nil, errTLSMaterial
	}
	file, err := openTLSMaterialFile(path)
	if err != nil {
		return nil, errTLSMaterial
	}
	var data []byte
	defer func() {
		closeErr := file.Close()
		if result != nil || closeErr != nil {
			clear(data)
			contents, result = nil, errTLSMaterial
		}
	}()
	opened, err := file.Stat()
	if err != nil || !sameTLSMaterialMetadata(before, opened) {
		return nil, errTLSMaterial
	}
	// The extra byte detects growth beyond the bound, rather than accepting a
	// valid PEM prefix. Stat alone does not bound bytes read from a changing file.
	data, err = io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) != opened.Size() || len(data) == 0 || int64(len(data)) > limit {
		return nil, errTLSMaterial
	}
	after, err := file.Stat()
	if err != nil || !sameTLSMaterialMetadata(opened, after) {
		return nil, errTLSMaterial
	}
	return data, nil
}

func sameTLSMaterialMetadata(left, right os.FileInfo) bool {
	return right != nil && right.Mode().IsRegular() && os.SameFile(left, right) &&
		left.Mode() == right.Mode() && left.Size() == right.Size() && left.ModTime().Equal(right.ModTime())
}
