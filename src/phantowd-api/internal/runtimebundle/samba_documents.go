// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

const sambaSettingsPath = "samba/smb.conf"

func boundedSambaDocuments(globals, passwd, group, nss, sections string) (map[string]string, error) {
	if globallen := int64(len(globals)); globallen == 0 || globallen > maxConfigurationBytes ||
		int64(len(sections)) > maxConfigurationBytes-globallen || passwd == "" || group == "" || nss == "" {
		return nil, ErrInvalid
	}
	documents := map[string]string{
		"passwd": passwd, "group": group, "nsswitch.conf": nss,
		"hosts": "127.0.0.1 localhost\n", "protocols": "tcp 6 TCP\nudp 17 UDP\n",
		"services": "microsoft-ds 445/tcp\n", sambaSettingsPath: globals + sections,
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
