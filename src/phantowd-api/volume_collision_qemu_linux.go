//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/volumeprobe"
)

// Probe-only XFS v4 geometry, matching the native generated-image test.
// These bytes are not a mountable filesystem and must never be mounted.
func qemuXFSProbeHeader() []byte {
	h := make([]byte, 512)
	copy(h, "XFSB")
	binary.BigEndian.PutUint32(h[4:], 4096)
	binary.BigEndian.PutUint64(h[8:], 4096)
	copy(h[32:48], []byte{0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0})
	for offset, value := range map[int]uint32{80: 1, 84: 4096, 88: 1} {
		binary.BigEndian.PutUint32(h[offset:], value)
	}
	for offset, value := range map[int]uint16{100: 4, 102: 512, 104: 256, 106: 16} {
		binary.BigEndian.PutUint16(h[offset:], value)
	}
	copy(h[120:125], []byte{12, 9, 8, 4, 12})
	return h
}

// Called only after the fixed QEMU virtual-device guard. source stays read-only;
// only newly created regular files under guest /run receive synthetic metadata.
func probeQEMUCollisions(source *os.File) error {
	ext := make([]byte, 4096)
	if _, err := source.ReadAt(ext, 0); err != nil {
		return err
	}
	xfs := qemuXFSProbeHeader()
	invalid := make([]byte, 512)
	copy(invalid, "XFSB")
	for _, fixture := range []struct {
		name   string
		ext    bool
		header []byte
		status string // empty means exact ErrProbe, never a successful result
	}{
		{"ext-only", true, nil, "ext-metadata"},
		{"xfs-only", false, xfs, "other-signature"},
		{"invalid-xfs", false, invalid, "unidentified"},
		{"xfs-ext-collision", true, xfs, ""},
	} {
		if err := probeQEMUCollisionImage(source, ext, fixture.ext, fixture.header, fixture.status); err != nil {
			return fmt.Errorf("QEMU metadata fixture %s: %w", fixture.name, err)
		}
	}
	fmt.Println("PHANTOWD_VOLUME_COLLISION_READY ext_control=true xfs_control=true invalid_control=true collision_refused=true partial_set_discarded=true hashes_unchanged=true scope=synthetic-regular-images")
	return nil
}

func probeQEMUCollisionImage(control *os.File, ext []byte, includeExt bool, header []byte, status string) error {
	output, err := os.CreateTemp("/run", "phantowd-collision-")
	if err != nil {
		return err
	}
	defer os.Remove(output.Name())
	defer output.Close()
	if err := output.Truncate(16 * 1024 * 1024); err != nil {
		return err
	}
	if includeExt {
		if _, err := output.WriteAt(ext, 0); err != nil {
			return err
		}
	}
	if _, err := output.WriteAt(header, 0); err != nil {
		return err
	}
	if err := output.Close(); err != nil {
		return err
	}
	input, err := os.Open(output.Name())
	if err != nil {
		return err
	}
	defer input.Close()
	before, err := qemuProbeImageHash(input)
	if err != nil {
		return err
	}
	result, err := runProbeFixture(input)
	if status == "" {
		if !errors.Is(err, volumeprobe.ErrProbe) || result != (volumeprobe.Result{}) {
			return errors.New("collision returned metadata or unexpected error")
		}
		// A valid first result cannot escape a set whose later input conflicts.
		snapshot, err := volumeprobe.ObserveSet(context.Background(), []*os.File{control, input})
		if !errors.Is(err, volumeprobe.ErrProbe) || len(snapshot.Results()) != 0 {
			return errors.New("collision escaped whole-set refusal")
		}
	} else {
		if err != nil || result.Status != status || result.SourceKind != "regular-image" {
			return errors.New("signature control did not match")
		}
		if includeExt {
			if result.Filesystem != "ext2" || result.FilesystemUUID != qemuNFSVolumeUUID {
				return errors.New("ext control identity mismatch")
			}
		} else if result.Filesystem != "" || result.FilesystemUUID != "" {
			return errors.New("non-ext control returned identity")
		}
	}
	after, err := qemuProbeImageHash(input)
	if err != nil || before != after {
		return errors.New("probe changed its generated image")
	}
	return nil
}

func qemuProbeImageHash(source *os.File) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	hash := sha256.New()
	// Independent offset, bounded streaming memory, and no read of device paths.
	n, err := io.Copy(hash, io.NewSectionReader(source, 0, 16*1024*1024))
	if err != nil || n != 16*1024*1024 {
		return result, errors.New("incomplete fixture hash")
	}
	copy(result[:], hash.Sum(nil))
	return result, nil
}
