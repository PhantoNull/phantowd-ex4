//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"net/netip"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
)

// NFSFixtureConfigurationQEMU renders disposable-profile data, not admission,
// identities, filesystem contents, daemon privileges or product persistence.
func NFSFixtureConfigurationQEMU(candidate fileserviceplan.NFSv3Candidate) (map[string]string, error) {
	enabled, table, roots, err := candidate.Documents()
	if err != nil {
		return nil, ErrInvalid
	}
	if !enabled {
		return nil, ErrUnavailable
	}
	for _, root := range roots {
		for _, client := range root.Clients {
			prefix, err := netip.ParsePrefix(client.Network)
			if err != nil || !prefix.Addr().Is4() {
				return nil, ErrInvalid
			}
		}
	}
	documents := map[string]string{
		"exports":       table,
		"nfs.conf":      "[mountd]\nstate-directory-path=/run/nfs\nreverse-lookup=n\nmanage-gids=n\n[nfsd]\nvers2=n\nvers3=y\nvers4=n\ntcp=y\nudp=n\n",
		"netconfig":     "local tpi_cots_ord - loopback - - -\ntcp tpi_cots_ord v inet tcp - -\n",
		"passwd":        "root:x:0:0:root:/:/sbin/nologin\ndaemon:x:1:1:daemon:/:/sbin/nologin\nnobody:x:65534:65534:nobody:/:/sbin/nologin\n",
		"group":         "root:x:0:\ndaemon:x:1:\nnogroup:x:65534:\n",
		"nsswitch.conf": "passwd: files\ngroup: files\nshadow: files\nhosts: files\nnetworks: files\nprotocols: files\nservices: files\n",
		"hosts":         "127.0.0.1 localhost\n",
		"protocols":     "tcp 6 TCP\n",
		"services":      "sunrpc 111/tcp rpcbind portmapper\nnfs 2049/tcp\nmountd 20048/tcp\n",
	}
	var total int64
	for _, value := range documents {
		total += int64(len(value))
	}
	if total > maxConfigurationBytes {
		return nil, ErrInvalid
	}
	return documents, nil
}
