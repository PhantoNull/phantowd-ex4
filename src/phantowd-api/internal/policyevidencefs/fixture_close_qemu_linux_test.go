//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policyevidencefs

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestCloseFaultMatrixWithoutMountAdmission(t *testing.T) {
	// Native WSL need not support unique mount IDs: this tests actual Close
	// over owned synthetic descriptors, NOT Open/Observe admission/lifecycle.
	for _, count := range []int{5, 6} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			root := t.TempDir()
			err := exerciseCloseFaultMatrixQEMU(context.Background(), count, func(boundary int, after bool) (*Observer, error) {
				dir := filepath.Join(root, fmt.Sprintf("%d-%t", boundary, after))
				if err := os.Mkdir(dir, 0700); err != nil {
					return nil, err
				}
				s := &state{watch: -1, closeFile: func(f *os.File) error { return f.Close() }}
				a := &Observer{state: s}
				s.self = a
				var err error
				s.watch, err = unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
				if err != nil {
					return nil, err
				}
				for index := range 3 {
					path := filepath.Join(dir, fmt.Sprintf("dir-%d", index))
					if err := os.Mkdir(path, 0700); err != nil {
						return nil, err
					}
					file, err := os.Open(path)
					if err != nil {
						return nil, err
					}
					s.dirs[index].file = file
					if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
						return nil, err
					}
				}
				for index := 0; index < count-3; index++ {
					file, err := os.CreateTemp(dir, "file-")
					if err != nil {
						return nil, err
					}
					s.files[index].file = file
				}
				return a, nil
			})
			if err != nil {
				t.Fatal("controlled close campaign", err)
			}
		})
	}
}
