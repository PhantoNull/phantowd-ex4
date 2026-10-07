//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import "github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"

// Exact existing native-fixture globals. Management and service documents must
// never choose different passdb/state paths or broaden the loopback profile.
const nativeSambaGlobalsQEMU = `[global]
server role = standalone server
security = user
map to guest = Never
interfaces = 127.0.0.1
bind interfaces only = yes
smb ports = 1445
server min protocol = SMB3_00
server max protocol = SMB3_11
server signing = mandatory
load printers = no
printing = bsd
printcap name = /dev/null
disable spoolss = yes
dns proxy = no
name resolve order = host
dos charset = CP850
unix charset = UTF-8
private dir = /state/private
lock directory = /state/lock
state directory = /state/state
cache directory = /state/cache
pid directory = /state/pid
ncalrpc dir = /state/rpc
passdb backend = tdbsam:/state/private/passdb.tdb
log file = /state/log.smbd
`

// SambaPlannedDataDocumentsQEMU performs bounded pure rendering from ONE
// immutable Plan candidate. It installs nothing, retains no authority and
// does not replace the fixed native runtime's configuration. A future trusted
// constructor must independently render expectations, bind exact original
// mounted roots and recheck complete evidence before any daemon admission.
func SambaPlannedDataDocumentsQEMU(candidate fileserviceplan.SambaIsolatedCandidate) (map[string]string, error) {
	passwd, group, nss, sections, roots, err := candidate.Documents()
	if err != nil || len(roots) == 0 {
		return nil, ErrInvalid
	}
	return boundedPlannedDocumentsQEMU(passwd, group, nss, sections)
}

func boundedPlannedDocumentsQEMU(passwd, group, nss, sections string) (map[string]string, error) {
	if passwd == "" || group == "" || nss == "" || sections == "" {
		return nil, ErrInvalid
	}
	documents := map[string]string{
		"passwd": passwd, "group": group, "nsswitch.conf": nss,
		"hosts": "127.0.0.1 localhost\n", "protocols": "tcp 6 TCP\nudp 17 UDP\n",
		"services":       "microsoft-ds 445/tcp\n",
		"samba/smb.conf": nativeSambaGlobalsQEMU + sections,
	}
	var size int64
	for _, contents := range documents {
		bytes := int64(len(contents))
		if bytes > maxConfigurationBytes-size {
			return nil, ErrInvalid
		}
		size += bytes
	}
	return documents, nil
}
