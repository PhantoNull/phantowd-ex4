//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"crypto/sha256"
	"testing"

	"golang.org/x/sys/unix"
)

func TestNFSSourceServerTableComparisonPreservesFullObservation(t *testing.T) {
	base := nfsServerTableQEMU{stamp: unix.Stat_t{Dev: 1, Ino: 2, Mode: unix.S_IFREG | 0600, Nlink: 1, Size: 3}, digest: sha256.Sum256([]byte("abc"))}
	if !sameNFSServerTableQEMU(base, base) {
		t.Fatal("identical observation refused")
	}
	for name, change := range map[string]func(*nfsServerTableQEMU){
		"device":   func(v *nfsServerTableQEMU) { v.stamp.Dev++ },
		"inode":    func(v *nfsServerTableQEMU) { v.stamp.Ino++ },
		"mode":     func(v *nfsServerTableQEMU) { v.stamp.Mode ^= 040 },
		"uid":      func(v *nfsServerTableQEMU) { v.stamp.Uid++ },
		"gid":      func(v *nfsServerTableQEMU) { v.stamp.Gid++ },
		"links":    func(v *nfsServerTableQEMU) { v.stamp.Nlink++ },
		"size":     func(v *nfsServerTableQEMU) { v.stamp.Size++ },
		"mtime":    func(v *nfsServerTableQEMU) { v.stamp.Mtim.Sec++ },
		"ctime":    func(v *nfsServerTableQEMU) { v.stamp.Ctim.Nsec++ },
		"contents": func(v *nfsServerTableQEMU) { v.digest[0] ^= 1 },
	} {
		t.Run(name, func(t *testing.T) {
			other := base
			change(&other)
			if sameNFSServerTableQEMU(base, other) || sameNFSServerTableQEMU(other, base) {
				t.Fatal("changed observation accepted")
			}
		})
	}
	read := base
	read.stamp.Atim.Sec++
	if !sameNFSServerTableQEMU(base, read) {
		t.Fatal("access time treated as export identity")
	}
}
