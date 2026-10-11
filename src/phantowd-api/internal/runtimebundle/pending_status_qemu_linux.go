//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Fixed, private producer observation, not a client-handle/request witness or
// product authority. The old planned/created parser and its eligibility remain
// unchanged. In particular, username equality cannot identify our client.
type pendingServerIDQEMU struct {
	PID      string `json:"pid"`
	TaskID   string `json:"task_id"`
	VNN      string `json:"vnn"`
	UniqueID string `json:"unique_id"`
}

type pendingStatusQEMU struct {
	server                     pendingServerIDQEMU
	session, tree              string
	device, inode, shareFileID uint64
}

// Accept one exact 4.22.11 session/tree/open for the pre-existing fixture.
// Missing, duplicate, null, ambiguous, aliased or unqualified fields refuse.
// Unknown producer fields may exist, but are still bounded/duplicate checked.
func parsePendingStatusQEMU(output []byte) (pendingStatusQEMU, error) {
	if len(output) == 0 || len(output) > 1<<20 || !utf8.Valid(output) || !canonicalPendingJSONQEMU(output) {
		return pendingStatusQEMU{}, ErrMismatch
	}
	var root struct {
		Version  string `json:"version"`
		Sessions map[string]struct {
			ID       string              `json:"session_id"`
			Username string              `json:"username"`
			UID      *uint32             `json:"uid"`
			GID      *uint32             `json:"gid"`
			Server   pendingServerIDQEMU `json:"server_id"`
		} `json:"sessions"`
		Trees map[string]struct {
			Service string              `json:"service"`
			Session string              `json:"session_id"`
			ID      string              `json:"tcon_id"`
			Server  pendingServerIDQEMU `json:"server_id"`
		} `json:"tcons"`
		Files map[string]struct {
			Path string `json:"service_path"`
			Name string `json:"filename"`
			ID   struct {
				Device *uint64 `json:"devid"`
				Inode  *uint64 `json:"inode"`
				ExtID  *uint64 `json:"extid"`
			} `json:"fileid"`
			Deletes *uint32 `json:"num_pending_deletes"`
			Opens   map[string]struct {
				Server pendingServerIDQEMU `json:"server_id"`
				UID    *uint32             `json:"uid"`
				ID     string              `json:"share_file_id"`
				Access struct {
					Hex   string `json:"hex"`
					Read  *bool  `json:"READ_DATA"`
					Write *bool  `json:"WRITE_DATA"`
				} `json:"access_mask"`
			} `json:"opens"`
		} `json:"open_files"`
	}
	if json.Unmarshal(output, &root) != nil || root.Version != "4.22.11" ||
		len(root.Sessions) != 1 || len(root.Trees) != 1 || len(root.Files) != 1 {
		return pendingStatusQEMU{}, fmt.Errorf("pending STATUS inventory sessions=%d trees=%d files=%d: %w", len(root.Sessions), len(root.Trees), len(root.Files), ErrMismatch)
	}
	var observed pendingStatusQEMU
	for key, session := range root.Sessions {
		if !pendingNumberQEMU(key, 64, true) || session.ID != key || session.Username != "qpsecond" ||
			session.UID == nil || *session.UID != 2001 || session.GID == nil || *session.GID != 2001 ||
			!pendingNumberQEMU(session.Server.PID, 32, true) || session.Server.PID == "1" ||
			session.Server.TaskID != "0" || session.Server.VNN != "4294967295" ||
			!pendingNumberQEMU(session.Server.UniqueID, 64, true) || session.Server.UniqueID == "18446744073709551615" {
			return pendingStatusQEMU{}, fmt.Errorf("pending STATUS session: %w", ErrMismatch)
		}
		observed.session, observed.server = key, session.Server
	}
	for key, tree := range root.Trees {
		if !pendingNumberQEMU(key, 32, true) || tree.ID != key || tree.Service != "writable" ||
			tree.Session != observed.session || tree.Server != observed.server {
			return pendingStatusQEMU{}, fmt.Errorf("pending STATUS tree: %w", ErrMismatch)
		}
		observed.tree = key
	}
	file, exists := root.Files["/shares/writable/pending-write"]
	if !exists || file.Path != "/shares/writable" || file.Name != "pending-write" ||
		file.ID.Device == nil || *file.ID.Device == 0 || file.ID.Inode == nil || *file.ID.Inode == 0 ||
		file.ID.ExtID == nil || *file.ID.ExtID != 0 || file.Deletes == nil || *file.Deletes != 0 || len(file.Opens) != 1 {
		return pendingStatusQEMU{}, fmt.Errorf("pending STATUS file: %w", ErrMismatch)
	}
	for key, open := range file.Opens {
		if !pendingNumberQEMU(open.ID, 64, true) || key != observed.server.PID+"/"+open.ID ||
			open.Server != observed.server || open.UID == nil || *open.UID != 2001 ||
			open.Access.Hex != "0x0012019f" || open.Access.Read == nil || !*open.Access.Read ||
			open.Access.Write == nil || !*open.Access.Write {
			return pendingStatusQEMU{}, fmt.Errorf("pending STATUS open: %w", ErrMismatch)
		}
		observed.shareFileID, _ = strconv.ParseUint(open.ID, 10, 64)
	}
	observed.device, observed.inode = *file.ID.Device, *file.ID.Inode
	return observed, nil
}

func pendingNumberQEMU(value string, bits int, nonzero bool) bool {
	number, err := strconv.ParseUint(value, 10, bits)
	return err == nil && (!nonzero || number != 0) && strconv.FormatUint(number, 10) == value
}

// Exact spelling for interpreted keys; UTF-8 bytes, depth, token count,
// duplicates (including unknown fields) and trailing JSON are also bounded.
func canonicalPendingJSONQEMU(data []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	remaining := 16384
	var scan func(int) bool
	scan = func(depth int) bool {
		remaining--
		if depth > 16 || remaining < 0 {
			return false
		}
		token, err := decoder.Token()
		if err != nil {
			return false
		}
		switch token {
		case json.Delim('{'):
			seen := make(map[string]bool)
			for decoder.More() {
				token, err := decoder.Token()
				key, ok := token.(string)
				if err != nil || !ok || seen[key] {
					return false
				}
				seen[key] = true
				canonical := strings.ToLower(key)
				switch canonical {
				case "version", "sessions", "tcons", "open_files", "session_id", "username", "uid", "gid", "server_id",
					"pid", "task_id", "vnn", "unique_id", "service", "tcon_id", "service_path", "filename", "fileid",
					"devid", "inode", "extid", "num_pending_deletes", "opens", "share_file_id", "access_mask", "hex":
				case "read_data", "write_data":
					canonical = strings.ToUpper(canonical)
				default:
					canonical = key
				}
				if key != canonical || !scan(depth+1) {
					return false
				}
			}
			end, err := decoder.Token()
			return err == nil && end == json.Delim('}')
		case json.Delim('['):
			for decoder.More() {
				if !scan(depth + 1) {
					return false
				}
			}
			end, err := decoder.Token()
			return err == nil && end == json.Delim(']')
		default:
			return true
		}
	}
	if !scan(0) {
		return false
	}
	_, err := decoder.Token()
	return errors.Is(err, io.EOF)
}
