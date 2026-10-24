// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import "github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"

const nfsProtocolDeclaration = "[nfsd]\nvers2=no\nvers3=yes\nvers4=no\ntcp=yes\nudp=no\n"

// Public libtirpc transport data, not a listener or client access policy.
const nfsRPCTransportData = `udp tpi_clts v inet udp - -
tcp tpi_cots_ord v inet tcp - -
udp6 tpi_clts v inet6 udp - -
tcp6 tpi_cots_ord v inet6 tcp - -
rawip tpi_raw - inet - - -
local tpi_cots_ord - loopback - - -
unix tpi_cots_ord - loopback - - -
`

// NFSv3Documents projects inert data from ONE Plan-bound candidate. A valid
// disabled policy returns false/nil/nil. Returned maps grant no authority:
// original roots, configuration search, mutable NSM state, options, helpers
// and kernel/service lifetimes require independent trusted qualification.
// No filesystem access, state initialization or executable invocation occurs.
func NFSv3Documents(candidate fileserviceplan.NFSv3Candidate) (bool, map[string]string, error) {
	enabled, table, _, err := candidate.Documents()
	if err != nil {
		return false, nil, ErrInvalid
	}
	if !enabled {
		return false, nil, nil
	}
	documents := map[string]string{
		"etc/exports": table, "etc/nfs.conf": nfsProtocolDeclaration, "etc/netconfig": nfsRPCTransportData,
	}
	var total int64
	for _, contents := range documents {
		if int64(len(contents)) > maxConfigurationBytes-total {
			return false, nil, ErrInvalid
		}
		total += int64(len(contents))
	}
	return true, documents, nil
}
