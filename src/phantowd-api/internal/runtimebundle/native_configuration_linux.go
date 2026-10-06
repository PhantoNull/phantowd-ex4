//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"crypto/sha256"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
)

// Expectations are derived from the opaque trusted native candidate, never
// measured from the directory being admitted. This is not a credential/service
// plan or a retained identity lease. The existing protected tree admission
// retains the complete census and independently checks bytes, modes and mounts.
func nativeLookupConfiguration(lookup fileserviceplan.SambaEnrollmentLookup) (*configurationPlan, error) {
	passwd, group, nss, err := lookup.LookupDocuments()
	if err != nil || lookup.Fingerprint() == [32]byte{} {
		return nil, ErrInvalid
	}
	files := make([]File, 0, 3)
	for name, value := range map[string]string{"passwd": passwd, "group": group, "nsswitch.conf": nss} {
		files = append(files, File{Path: name, Size: int64(len(value)), Mode: 0644, SHA256: sha256.Sum256([]byte(value))})
	}
	return newConfigurationPlan(files)
}
