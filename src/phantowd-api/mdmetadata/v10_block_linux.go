//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package mdmetadata

import (
	"os"
	"runtime"
	"unsafe"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/volumeprobe"
	"golang.org/x/sys/unix"
)

// InspectBlock reads one selected GPT partition through a caller-owned
// generation-bound O_RDONLY whole-disk descriptor. The caller must have
// already established a complete eligible inventory and validated partition
// geometry. The function rechecks major/minor, diskseq, logical sector size
// and device capacity around the bounded read. It opens no path and performs
// no assembly, mount or mutation.
func InspectBlock(source *os.File, generation volumeprobe.BlockDeviceGeneration, sourceBytes uint64, partition Partition) (Observation, error) {
	if source == nil || (generation.Major == 0 && generation.Minor == 0) || generation.DiskSequence == 0 ||
		sourceBytes == 0 || sourceBytes > uint64(^uint64(0)>>1) || sourceBytes%logicalSectorBytes != 0 {
		return Observation{}, ErrUnsafeSource
	}
	fd := int(source.Fd())
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY || flags&unix.O_PATH != 0 {
		return Observation{}, ErrUnsafeSource
	}
	before, err := blockState(fd, generation, sourceBytes)
	if err != nil {
		return Observation{}, err
	}
	result, err := InspectPartition(source, int64(sourceBytes), partition)
	if err != nil {
		return Observation{}, err
	}
	after, err := blockState(fd, generation, sourceBytes)
	if err != nil || !sameBlockState(before, after) {
		return Observation{}, ErrUnsafeSource
	}
	return result, nil
}

type blockStateSnapshot struct {
	stat       unix.Stat_t
	diskseq    uint64
	bytes      uint64
	sectorSize int
}

func blockState(fd int, generation volumeprobe.BlockDeviceGeneration, expectedBytes uint64) (blockStateSnapshot, error) {
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFBLK ||
		uint32(unix.Major(uint64(stat.Rdev))) != generation.Major ||
		uint32(unix.Minor(uint64(stat.Rdev))) != generation.Minor {
		return blockStateSnapshot{}, ErrUnsafeSource
	}
	diskseq, err := ioctlUint64(fd, unix.BLKGETDISKSEQ)
	if err != nil || diskseq == 0 || diskseq != generation.DiskSequence {
		return blockStateSnapshot{}, ErrUnsafeSource
	}
	size, err := ioctlUint64(fd, unix.BLKGETSIZE64)
	if err != nil || size == 0 || size != expectedBytes {
		return blockStateSnapshot{}, ErrUnsafeSource
	}
	sectorSize, err := unix.IoctlGetInt(fd, unix.BLKSSZGET)
	if err != nil || sectorSize != int(logicalSectorBytes) {
		return blockStateSnapshot{}, ErrUnsafeSource
	}
	return blockStateSnapshot{stat: stat, diskseq: diskseq, bytes: size, sectorSize: sectorSize}, nil
}

func ioctlUint64(fd int, request uint) (uint64, error) {
	var value uint64
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(request), uintptr(unsafe.Pointer(&value)))
	runtime.KeepAlive(&value)
	if errno != 0 {
		return 0, errno
	}
	return value, nil
}

func sameBlockState(left, right blockStateSnapshot) bool {
	return left.stat.Dev == right.stat.Dev && left.stat.Ino == right.stat.Ino &&
		left.stat.Rdev == right.stat.Rdev && left.stat.Mode == right.stat.Mode &&
		left.diskseq == right.diskseq && left.bytes == right.bytes && left.sectorSize == right.sectorSize
}
