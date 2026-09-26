// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package unixidentity

import "strings"

const MaxNSSBytes = 64 << 10

// FilesOnlyNSS validates the deliberately narrow supported identity profile.
// passwd/group must appear exactly once with only files. If initgroups is
// supplied it must also be files-only. Other databases do not establish identity
// completeness; their sources are not restricted by this check.
func FilesOnlyNSS(data []byte) bool {
	if len(data) == 0 || len(data) > MaxNSSBytes {
		return false
	}
	for _, c := range data {
		if c != '\n' && c != '\t' && (c < 32 || c > 126) {
			return false
		}
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		if len(line) > MaxLineBytes {
			return false
		}
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			return false
		}
		key := strings.TrimSpace(parts[0])
		if key == "" || strings.ContainsAny(key, " \t[]\\") {
			return false
		}
		// Reject differently-cased spellings rather than silently ignoring a
		// potentially meaningful duplicate on another libc/version.
		folded := strings.ToLower(key)
		if folded == "passwd" || folded == "group" || folded == "initgroups" {
			if key != folded || seen[key] || strings.TrimSpace(parts[1]) != "files" {
				return false
			}
			seen[key] = true
		}
	}
	return seen["passwd"] && seen["group"]
}
