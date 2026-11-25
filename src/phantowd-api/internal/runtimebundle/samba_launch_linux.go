//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"regexp"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/configjson"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
	"golang.org/x/sys/unix"
)

const (
	sambaLaunchFormat = "phantowd-rc0-samba-launch-v1"
	sambaLaunchLimit  = 16 << 10
	sambaLaunchSeals  = unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
)

var sambaLaunchShareID = regexp.MustCompile("^[a-z][a-z0-9-]{0,63}$")

// SambaLaunchRole describes how the corresponding inherited share descriptor
// must be mounted. The manifest is separate from code and mount authority.
type SambaLaunchRole struct {
	ID       string `json:"id"`
	ReadOnly bool   `json:"read_only"`
}

// SealSambaLaunchDeclaration preserves candidate order and modes. The caller
// verifies the same candidate against the retained mount roster, and supplies
// its descriptors in the same order after the fixed startup roles.
func SealSambaLaunchDeclaration(candidate fileserviceplan.SambaIsolatedCandidate) (_ *os.File, result error) {
	_, _, _, _, roots, err := candidate.Documents()
	if err != nil || len(roots) == 0 || len(roots) > shareconfig.MaxShares || os.Getuid() != 0 || os.Geteuid() != 0 {
		return nil, ErrInvalid
	}
	declaration := struct {
		Format string            `json:"format"`
		Shares []SambaLaunchRole `json:"shares"`
	}{sambaLaunchFormat, make([]SambaLaunchRole, 0, len(roots))}
	for _, root := range roots {
		declaration.Shares = append(declaration.Shares, SambaLaunchRole{ID: root.ID, ReadOnly: root.ReadOnly})
	}
	data, err := json.Marshal(declaration)
	if err != nil || len(data) > sambaLaunchLimit {
		return nil, ErrInvalid
	}
	fd, err := unix.MemfdCreate("phantowd-samba-launch", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "samba-launch-declaration")
	defer func() {
		if result != nil {
			result = errors.Join(result, file.Close())
		}
	}()
	if _, err := file.Write(data); err != nil {
		return nil, err
	}
	// Set an explicit owner and group independent of the caller's umask.
	if err := errors.Join(file.Chown(0, 0), file.Chmod(0400)); err != nil {
		return nil, err
	}
	if _, err := unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, sambaLaunchSeals); err != nil {
		return nil, err
	}
	return file, nil
}

// ReadSambaLaunchDeclaration accepts only a root-owned sealed memory file.
// The caller retains ownership of the descriptor.
func ReadSambaLaunchDeclaration(file *os.File) ([]SambaLaunchRole, error) {
	if file == nil {
		return nil, ErrInvalid
	}
	var st unix.Stat_t
	var fs unix.Statfs_t
	fd := int(file.Fd())
	seals, err := unix.FcntlInt(file.Fd(), unix.F_GET_SEALS, 0)
	if err != nil || seals&sambaLaunchSeals != sambaLaunchSeals || unix.Fstat(fd, &st) != nil || st.Mode != unix.S_IFREG|0400 ||
		st.Uid != 0 || st.Gid != 0 || st.Size <= 0 || st.Size > sambaLaunchLimit ||
		unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.TMPFS_MAGIC {
		return nil, ErrInvalid
	}
	data := make([]byte, st.Size)
	if _, err := file.ReadAt(data, 0); err != nil {
		return nil, err
	}
	return decodeSambaLaunchDeclaration(data)
}

func decodeSambaLaunchDeclaration(data []byte) ([]SambaLaunchRole, error) {
	var declaration struct {
		Format string `json:"format"`
		Shares []struct {
			ID       string `json:"id"`
			ReadOnly *bool  `json:"read_only"`
		} `json:"shares"`
	}
	keys := map[string]bool{"format": true, "shares": true, "id": true, "read_only": true}
	if configjson.Decode(bytes.NewReader(data), &declaration, sambaLaunchLimit, 4, keys) != nil ||
		declaration.Format != sambaLaunchFormat || len(declaration.Shares) == 0 || len(declaration.Shares) > shareconfig.MaxShares {
		return nil, ErrInvalid
	}
	seen := make(map[string]bool, len(declaration.Shares))
	roles := make([]SambaLaunchRole, 0, len(declaration.Shares))
	for _, share := range declaration.Shares {
		if !sambaLaunchShareID.MatchString(share.ID) || share.ReadOnly == nil || seen[share.ID] {
			return nil, ErrInvalid
		}
		seen[share.ID] = true
		roles = append(roles, SambaLaunchRole{ID: share.ID, ReadOnly: *share.ReadOnly})
	}
	return roles, nil
}
