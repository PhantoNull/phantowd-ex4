//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
	"golang.org/x/sys/unix"
)

// A NEW fixed data profile after the prior native runtime and identity Owner
// are fully closed. This is individual descriptor/SMB access qualification,
// not continuous complete-roster/identity authority or product activation.
func nativeDataFixtureQEMU(plan *runtimebundle.Plan, lookup fileserviceplan.SambaEnrollmentLookup) error {
	return nativeDataFixtureProfileQEMU(plan, lookup, false)
}

func nativeDataFixtureProfileQEMU(plan *runtimebundle.Plan, lookup fileserviceplan.SambaEnrollmentLookup, pending bool) error {
	return nativeDataFixtureModeQEMU(plan, lookup, pending, false)
}

// Strong references survive the qualified fault until subprocess disposal.
var pendingPeerExitOriginalsQEMU []*os.File

func nativeDataFixtureModeQEMU(plan *runtimebundle.Plan, lookup fileserviceplan.SambaEnrollmentLookup, pending, peerExit bool) error {
	return nativeDataFixtureHandleModeQEMU(plan, lookup, pending, peerExit, false)
}

func nativeDataFixtureHandleModeQEMU(plan *runtimebundle.Plan, lookup fileserviceplan.SambaEnrollmentLookup, pending, peerExit, handle bool) error {
	if handle && (!pending || peerExit) {
		return errors.New("invalid handle fixture profile")
	}
	if peerExit && !pending {
		return errors.New("invalid peer-exit fixture profile")
	}
	started := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	if !pending {
		reportNativeDataTimingQEMU(nativeDataEnteredQEMU, started)
	}
	const config = "/run/phantowd-native-data-config"
	const root = "/run/phantowd-native-samba-root"
	const handoff = "/run/phantowd-native-data-roots"
	const source = "/run/phantowd-samba-source"
	const contents = "native-share-qualified"
	documents, err := runtimebundle.SambaNativeDataDocumentsQEMU(lookup)
	if err != nil {
		return err
	}
	for _, path := range []string{config, config + "/samba", root + "/shares", root + "/shares/readonly", root + "/shares/writable", handoff, handoff + "/readonly", handoff + "/writable"} {
		if err := os.Mkdir(path, 0755); err != nil {
			return err
		}
	}
	for name, contents := range documents {
		mode := os.FileMode(0644)
		if name == "samba/smb.conf" {
			mode = 0600
		}
		file, err := os.OpenFile(config+"/"+name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if err != nil {
			return err
		}
		_, err = file.WriteString(contents)
		if err := errors.Join(err, file.Close()); err != nil {
			return err
		}
	}
	if err := unix.Mount(config, config, "", unix.MS_BIND, ""); err != nil {
		return err
	}
	if err := unix.Mount("", config, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		return err
	}
	for _, name := range []string{"readonly", "writable"} {
		path := source + "/native-" + name
		if err := os.Mkdir(path, 0770); err != nil {
			return err
		}
		if err := errors.Join(os.Chown(path, 2001, 2001), os.Chmod(path, 0770)); err != nil {
			return err
		}
	}
	for _, path := range []string{source + "/native-readonly/seed", "/run/native-share-upload"} {
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		_, err = file.WriteString(contents)
		if err := errors.Join(err, file.Close()); err != nil {
			return err
		}
	}
	if err := os.Chown(source+"/native-readonly/seed", 2001, 2001); err != nil {
		return err
	}
	if err := os.Symlink(source+"/native-readonly/seed", source+"/native-readonly/escape"); err != nil {
		return err
	}
	if pending {
		file, err := os.OpenFile(source+"/native-writable/pending-write", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		data := make([]byte, 4096)
		for index := range data {
			data[index] = 0x3c
		}
		written, writeErr := file.Write(data)
		closeErr := file.Close()
		if written != len(data) || writeErr != nil || closeErr != nil {
			return errors.Join(errors.New("synthetic pending object construction"), writeErr, closeErr)
		}
		if err := os.Chown(source+"/native-writable/pending-write", 2001, 2001); err != nil {
			return err
		}
	}
	var roots [2]*os.File
	for index, name := range []string{"readonly", "writable"} {
		roots[index], err = nativeDataRootCloneQEMU(source+"/native-"+name, handoff+"/"+name, index == 0)
		if err != nil {
			return err // No cleanup retry of uncertain mount operations.
		}
	}
	var callers [3]*os.File
	for index, path := range []string{"/run/phantowd-samba-code", config, "/run/phantowd-native-samba-state"} {
		fd, err := unix.Open(path, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		callers[index] = os.NewFile(uintptr(fd), "native-data-fixture-caller")
	}
	if !pending {
		reportNativeDataTimingQEMU(nativeDataPreparedQEMU, started)
	}
	var probeErr error
	if peerExit {
		pendingPeerExitOriginalsQEMU = append(pendingPeerExitOriginalsQEMU, callers[:]...)
		pendingPeerExitOriginalsQEMU = append(pendingPeerExitOriginalsQEMU, roots[:]...)
		probeErr = plan.ProbeNativePendingPeerExitQEMU(ctx, callers[0], callers[1], callers[2], lookup, roots)
	} else if handle {
		probeErr = plan.ProbeNativePendingHandleQEMU(ctx, callers[0], callers[1], callers[2], lookup, roots)
	} else if pending {
		probeErr = plan.ProbeNativePendingClientQEMU(ctx, callers[0], callers[1], callers[2], lookup, roots)
	} else {
		probeErr = plan.ProbeNativeDataDescriptorQEMU(ctx, callers[0], callers[1], callers[2], lookup, roots)
	}
	if probeErr != nil {
		return probeErr // Test process exit disposes a failed/quarantined experiment.
	}
	if !pending {
		reportNativeDataTimingQEMU(nativeDataProbedQEMU, started)
	}
	if peerExit {
		return nil // Reviewed originals/clones are NOT released as healthy cleanup.
	}
	// Successful probe already stopped/reaped every owned client and daemon and
	// closed their copies. Only then release originals/detach controller clones.
	for _, caller := range callers {
		if err := caller.Close(); err != nil {
			return err
		}
	}
	for index, name := range []string{"readonly", "writable"} {
		if err := roots[index].Close(); err != nil {
			return err
		}
		if err := unix.Unmount(handoff+"/"+name, 0); err != nil {
			return err
		}
	}
	// Only this successful, fully closed disposable experiment's client files.
	// The later complete-authority tracer must prove NEW transfers, not accept
	// byte-identical downloads left by this independent prerequisite.
	paths := []string{"/run/native-share-upload"}
	if !pending {
		paths = append(paths, "/run/native-share-download-rw", "/run/native-share-download-ro")
	}
	for _, path := range paths {
		if err := os.Remove(path); err != nil {
			return err
		}
	}
	if !pending {
		reportNativeDataTimingQEMU(nativeDataClosedQEMU, started)
	}
	return nil
}

func nativeDataRootCloneQEMU(source, destination string, readOnly bool) (*os.File, error) {
	fd, err := unix.Open(source, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	clone, err := unix.OpenTree(fd, "", unix.OPEN_TREE_CLONE|unix.OPEN_TREE_CLOEXEC|unix.AT_EMPTY_PATH)
	if err != nil {
		return nil, err
	}
	defer unix.Close(clone)
	attributes := uint64(unix.MOUNT_ATTR_NOSUID | unix.MOUNT_ATTR_NODEV | unix.MOUNT_ATTR_NOEXEC)
	if readOnly {
		attributes |= unix.MOUNT_ATTR_RDONLY
	}
	if err := unix.MountSetattr(clone, "", unix.AT_EMPTY_PATH, &unix.MountAttr{Attr_set: attributes}); err != nil {
		return nil, err
	}
	if err := unix.MoveMount(clone, "", unix.AT_FDCWD, destination, unix.MOVE_MOUNT_F_EMPTY_PATH); err != nil {
		return nil, err
	}
	root, err := unix.Open(destination, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(root), "native-data-original-clone"), nil
}
