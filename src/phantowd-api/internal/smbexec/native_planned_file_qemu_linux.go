//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package smbexec

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
)

// NativePlannedOpenFileQEMU is a private point-in-time STATUS observation of
// ONE fixed disposable writable/created open. It is NOT a retained file, proof
// of matching an Owner-held disk object, recovery or activation authority.
// A containing coordinator must independently retain/match the actual object
// and recheck complete storage/identity authority before this can be composed.
type NativePlannedOpenFileQEMU struct {
	backend     *NativeBackendQEMU
	session     smbStatusSession
	treeID      string
	device      uint64
	inode       uint64
	shareFileID uint64
}

var ErrNativePlannedOpenFileChangedQEMU = errors.New("native original planned open file changed")

var errNativePlannedOpenFileAbsentQEMU = errors.New("native planned file inventory is empty")

func (NativePlannedOpenFileQEMU) MarshalJSON() ([]byte, error) {
	return nil, errors.New("native file observation is not serializable")
}

func (*NativePlannedOpenFileQEMU) UnmarshalJSON([]byte) error {
	return errors.New("native file observation cannot be deserialized")
}

func (b *NativeBackendQEMU) ObservePlannedOpenFileQEMU(ctx context.Context) (NativePlannedOpenFileQEMU, error) {
	observed, err := b.readPlannedOpenFileQEMU(ctx)
	if errors.Is(err, errNativePlannedOpenFileAbsentQEMU) {
		return NativePlannedOpenFileQEMU{}, ErrUnavailable
	}
	if err != nil {
		return NativePlannedOpenFileQEMU{}, err
	}
	observed.backend = b
	return observed, nil
}

func (b *NativeBackendQEMU) VerifyPlannedOpenFileQEMU(ctx context.Context, before NativePlannedOpenFileQEMU) error {
	if b == nil || before.backend != b || before.session.SessionID == "" || before.session.Username != "qpsecond" ||
		before.treeID == "" || before.device == 0 || before.inode == 0 || before.shareFileID == 0 {
		return ErrInvalid
	}
	observed, err := b.readPlannedOpenFileQEMU(ctx)
	if errors.Is(err, errNativePlannedOpenFileAbsentQEMU) {
		return ErrNativePlannedOpenFileChangedQEMU
	}
	if err != nil {
		return err // Unavailable/malformed/canceled is NOT an observed change.
	}
	observed.backend = b
	if observed != before {
		return ErrNativePlannedOpenFileChangedQEMU
	}
	return nil
}

func (b *NativeBackendQEMU) readPlannedOpenFileQEMU(ctx context.Context) (NativePlannedOpenFileQEMU, error) {
	if b == nil || ctx == nil {
		return NativePlannedOpenFileQEMU{}, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return NativePlannedOpenFileQEMU{}, err
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.closed || b.inner == nil {
		return NativePlannedOpenFileQEMU{}, ErrInvalid
	}
	b.inner.mu.RLock()
	defer b.inner.mu.RUnlock()
	if b.inner.closed || b.inner.config == nil || b.inner.runner == nil {
		return NativePlannedOpenFileQEMU{}, ErrInvalid
	}
	// The fixed status operation, both-side runtime admission and existing
	// native observation budget are unchanged. No path/command is caller chosen.
	statusCtx, cancel := context.WithTimeout(ctx, 2*sessionStatusTimeout)
	defer cancel()
	output, err := b.inner.runner.Run(statusCtx, smbstatusPath,
		[]string{"-j", "-s", configArgument}, b.inner.config, nil, true)
	defer clear(output)
	if err != nil || statusCtx.Err() != nil {
		return NativePlannedOpenFileQEMU{}, errors.Join(ErrUnavailable, statusCtx.Err())
	}
	observed, parseErr := parsePlannedOpenFileQEMU(output)
	if err := statusCtx.Err(); err != nil {
		return NativePlannedOpenFileQEMU{}, errors.Join(ErrUnavailable, err)
	}
	return observed, parseErr
}

func parsePlannedOpenFileQEMU(output []byte) (NativePlannedOpenFileQEMU, error) {
	sessions, err := nativeSessionsQEMU(output) // Bounds, duplicate keys, EVERY session/generation.
	if err != nil || len(sessions) != 1 || !canonicalPlannedFileFieldsQEMU(output) {
		return NativePlannedOpenFileQEMU{}, ErrUnavailable
	}
	var root struct {
		Version  string `json:"version"`
		Sessions map[string]struct {
			UID uint32 `json:"uid"`
			GID uint32 `json:"gid"`
		} `json:"sessions"`
		Trees map[string]struct {
			Service   string            `json:"service"`
			SessionID string            `json:"session_id"`
			TreeID    string            `json:"tcon_id"`
			ServerID  smbStatusServerID `json:"server_id"`
		} `json:"tcons"`
		Files map[string]struct {
			ServicePath string `json:"service_path"`
			Filename    string `json:"filename"`
			FileID      struct {
				Device *uint64 `json:"devid"`
				Inode  *uint64 `json:"inode"`
				ExtID  *uint64 `json:"extid"`
			} `json:"fileid"`
			PendingDeletes *uint32 `json:"num_pending_deletes"`
			Opens          map[string]struct {
				ServerID    smbStatusServerID `json:"server_id"`
				UID         uint32            `json:"uid"`
				ShareFileID string            `json:"share_file_id"`
				Access      struct {
					Hex   string `json:"hex"`
					Read  bool   `json:"READ_DATA"`
					Write bool   `json:"WRITE_DATA"`
				} `json:"access_mask"`
			} `json:"opens"`
		} `json:"open_files"`
	}
	if json.Unmarshal(output, &root) != nil || root.Version != "4.22.11" || len(root.Trees) != 1 || root.Files == nil || len(root.Files) > 1 {
		return NativePlannedOpenFileQEMU{}, ErrUnavailable
	}
	observed := NativePlannedOpenFileQEMU{}
	for id, session := range sessions {
		if session.Username != "qpsecond" || root.Sessions[id].UID != 2001 || root.Sessions[id].GID != 2001 {
			return NativePlannedOpenFileQEMU{}, ErrUnavailable
		}
		observed.session = session
	}
	for id, tree := range root.Trees {
		number, err := strconv.ParseUint(id, 10, 32)
		if err != nil || number == 0 || strconv.FormatUint(number, 10) != id || tree.TreeID != id ||
			tree.Service != "Writable" || tree.SessionID != observed.session.SessionID || tree.ServerID != observed.session.ServerID {
			return NativePlannedOpenFileQEMU{}, ErrUnavailable
		}
		observed.treeID = id
	}
	if len(root.Files) == 0 {
		return NativePlannedOpenFileQEMU{}, errNativePlannedOpenFileAbsentQEMU
	}
	file, present := root.Files["/shares/writable/created"]
	if !present || file.ServicePath != "/shares/writable" || file.Filename != "created" ||
		file.FileID.Device == nil || *file.FileID.Device == 0 || file.FileID.Inode == nil || *file.FileID.Inode == 0 ||
		file.FileID.ExtID == nil || *file.FileID.ExtID != 0 || file.PendingDeletes == nil || *file.PendingDeletes != 0 || len(file.Opens) != 1 {
		return NativePlannedOpenFileQEMU{}, ErrUnavailable
	}
	for key, open := range file.Opens {
		id, err := strconv.ParseUint(open.ShareFileID, 10, 64)
		if err != nil || id == 0 || strconv.FormatUint(id, 10) != open.ShareFileID ||
			key != observed.session.ServerID.PID+"/"+open.ShareFileID || open.ServerID != observed.session.ServerID ||
			open.UID != 2001 || open.Access.Hex != "0x00000003" || !open.Access.Read || !open.Access.Write {
			return NativePlannedOpenFileQEMU{}, ErrUnavailable
		}
		observed.shareFileID = id
	}
	observed.device, observed.inode = *file.FileID.Device, *file.FileID.Inode
	return observed, nil
}

// Reject encoding/json's case-insensitive aliases for the fields this fixed
// observation interprets. Unknown producer fields remain allowed. This is
// specific to this pinned fixture, not a change to the general status reader.
// The existing status reader has already checked size, depth and duplicates.
func canonicalPlannedFileFieldsQEMU(output []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(output))
	decoder.UseNumber()
	var value func() bool
	value = func() bool {
		token, err := decoder.Token()
		if err != nil {
			return false
		}
		switch token {
		case json.Delim('{'):
			for decoder.More() {
				token, err := decoder.Token()
				key, ok := token.(string)
				if err != nil || !ok {
					return false
				}
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
				if key != canonical || !value() {
					return false
				}
			}
			end, err := decoder.Token()
			return err == nil && end == json.Delim('}')
		case json.Delim('['):
			for decoder.More() {
				if !value() {
					return false
				}
			}
			end, err := decoder.Token()
			return err == nil && end == json.Delim(']')
		default:
			return true
		}
	}
	return value()
}
