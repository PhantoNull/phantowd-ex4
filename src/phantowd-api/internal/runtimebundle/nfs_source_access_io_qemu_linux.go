//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"golang.org/x/sys/unix"
)

const nfsSourceClientsQEMU = "/run/phantowd-nfs-source-clients"
const nfsSourcePayloadQEMU = "phantowd-original-source-write\n"
const nfsSourceExportHandoffQEMU = "PHANTOWD_NFS_SOURCE_EXPORT_HANDOFF private_view=true caps=dac-read-search sources=3 flush=4 fixed_exportfs=true\n"

func (o *NFSSourceAccessQEMU) export(ctx context.Context, s *nfsCodeLifetimeQEMU, role processowner.NFSSourceExportOperationQEMU) error {
	program := s.code.files["usr/sbin/exportfs"]
	for _, alias := range s.code.plan.aliases {
		if alias.Path == "usr/sbin/exportfs" {
			program = s.code.files[alias.Target]
		}
	}
	if program == nil || o.capture != nil || s.revalidate(ctx) != nil {
		return ErrMismatch
	}
	extra := [10]*os.File{o.data[0], o.data[1], o.data[2], o.features, o.channels.flush[0], o.channels.flush[1], o.channels.flush[2], o.channels.flush[3], o.channels.namespaces[0], o.volume}
	var err error
	o.capture, err = processowner.NewNFSSourceExportCaptureQEMU(role, o.bootstrap, o.input, [4]*os.File{s.code.root, s.configuration.contents.root, s.state.root, program}, extra)
	if err != nil {
		return err
	}
	result, err := o.capture.Capture(ctx)
	if err != nil {
		return err
	}
	if result.Kind != processowner.CaptureExited || result.ExitCode != 0 || len(result.Stdout) != 0 || string(result.Stderr) != nfsSourceExportHandoffQEMU {
		fmt.Fprintf(os.Stderr, "PHANTOWD_NFS_SOURCE_EXPORT_FAILURE role=%s kind=%d exit=%d stderr=%q\n", role, result.Kind, result.ExitCode, result.Stderr)
		return ErrMismatch
	}
	return o.closeCapture(ctx)
}

func (o *NFSSourceAccessQEMU) closeCapture(ctx context.Context) error {
	settled, err := o.capture.Settled(ctx)
	if err != nil || !settled {
		return errors.Join(ErrReviewRequired, err)
	}
	if err := o.capture.Close(ctx); err != nil {
		return err
	}
	o.capture = nil
	return nil
}

// Fixed test client only, inherited root privilege is confined to this guest.
// The executable comes from the verified read-only base, not the server role.
// The generic launcher and its profile are not changed.
func (o *NFSSourceAccessQEMU) mountClient(ctx context.Context, index int) (processowner.CaptureResult, error) {
	if index < 0 || index > 2 || o.capture != nil {
		return processowner.CaptureResult{}, ErrInvalid
	}
	path := nfsSourceClientsQEMU + "/" + nfsSourceDataNamesQEMU[index]
	var before unix.Statx_t
	if err := sourceClientStatQEMU(path, &before); err != nil {
		return processowner.CaptureResult{}, err
	}
	var err error
	o.clientCode, err = os.Open("/sbin/mount.nfs")
	if err != nil {
		return processowner.CaptureResult{}, err
	}
	o.capture, err = processowner.NewCapture(processowner.CaptureSpec{ExecutableLabel: "/sbin/mount.nfs", Args: []string{"-n", "127.0.0.1:" + nfsSourceAnchorQEMU + "/" + nfsSourceDataNamesQEMU[index], path, "-o", "vers=3,proto=tcp,sec=sys,nolock,rw,soft,timeo=5,retrans=1,retry=0,port=2049,mountport=20048"}, RunAs: &processowner.Credentials{UID: 0, GID: 0}, Timeout: 10 * time.Second, StopTimeout: time.Second}, o.clientCode, o.input)
	if err != nil {
		return processowner.CaptureResult{}, err
	}
	if err := o.clientCode.Close(); err != nil {
		return processowner.CaptureResult{}, err
	}
	o.clientCode = nil
	result, err := o.capture.Capture(ctx)
	if err != nil {
		return processowner.CaptureResult{}, err
	}
	if result.Kind != processowner.CaptureExited {
		return processowner.CaptureResult{}, ErrMismatch
	}
	if result.ExitCode == 0 {
		o.mounts = append(o.mounts, nfsSourceClientMountQEMU{path: path, before: before})
		var fs unix.Statfs_t
		if unix.Statfs(path, &fs) != nil || fs.Type != unix.NFS_SUPER_MAGIC {
			return processowner.CaptureResult{}, ErrMismatch
		}
	} else {
		var after unix.Statx_t
		if sourceClientStatQEMU(path, &after) != nil || !sameMountdChannelQEMU(before, after) {
			return processowner.CaptureResult{}, ErrReviewRequired
		}
	}
	if err := o.closeCapture(ctx); err != nil {
		return processowner.CaptureResult{}, err
	}
	return result, nil
}

func sourceClientStatQEMU(path string, st *unix.Statx_t) error {
	const mask = unix.STATX_BASIC_STATS | unix.STATX_MNT_ID_UNIQUE
	if err := unix.Statx(unix.AT_FDCWD, path, unix.AT_SYMLINK_NOFOLLOW|unix.AT_NO_AUTOMOUNT, mask, st); err != nil || st.Mask&mask != mask || st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return ErrMismatch
	}
	return nil
}

func (o *NFSSourceAccessQEMU) exerciseIO(ctx context.Context, s *nfsCodeLifetimeQEMU) (result error) {
	phase := "activate"
	defer func() {
		if result != nil && !(o.sourceLoss && o.lossTriggered && errors.Is(result, errNFSSourceLossQEMU)) {
			fmt.Fprintf(os.Stderr, "PHANTOWD_NFS_SOURCE_IO_FAILURE phase=%s\n", phase)
		}
	}()
	o.exportsLoaded = true // Any uncertain command keeps kernel, daemons and sources.
	if err := o.export(ctx, s, processowner.NFSSourceActivateQEMU); err != nil {
		return err
	}
	// mountlist_add first opens rmtab r+ before its append fallback. Supply
	// the required empty fixture state instead of accepting that error notice.
	rmtab, err := os.OpenFile(nfsStateViewQEMU+"/nfs/rmtab", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if err := rmtab.Close(); err != nil {
		return err
	}
	if err := os.Mkdir(nfsSourceClientsQEMU, 0700); err != nil {
		return err
	}
	for _, name := range nfsSourceDataNamesQEMU {
		if err := os.Mkdir(nfsSourceClientsQEMU+"/"+name, 0700); err != nil {
			return err
		}
	}
	phase = "mount-clients"
	for index := 0; index < 3; index++ {
		result, err := o.mountClient(ctx, index)
		if err != nil {
			return err
		}
		if index == 2 {
			if result.ExitCode == 0 || !strings.Contains(string(result.Stderr), "access denied by server") {
				return ErrMismatch
			}
		} else if result.ExitCode != 0 || len(result.Stdout) != 0 || len(result.Stderr) != 0 {
			return ErrMismatch
		}
	}
	phase = "rw-private-source"
	file, err := os.OpenFile(nfsSourceClientsQEMU+"/books/created", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := file.WriteString(nfsSourcePayloadQEMU)
	if err := errors.Join(writeErr, file.Sync(), file.Close()); err != nil {
		return err
	}
	data, err := os.ReadFile(nfsSourceClientsQEMU + "/books/created")
	if err != nil || string(data) != nfsSourcePayloadQEMU {
		return ErrMismatch
	}
	fd, err := unix.Openat2(int(o.data[0].Fd()), "created", &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV})
	if err != nil {
		return err
	}
	local := os.NewFile(uintptr(fd), "nfs-original-source-client-write")
	var st unix.Stat_t
	data, readErr := io.ReadAll(io.LimitReader(local, 1024))
	statErr := unix.Fstat(fd, &st)
	if err := errors.Join(readErr, statErr, local.Close()); err != nil {
		return err
	}
	if string(data) != nfsSourcePayloadQEMU || st.Mode != unix.S_IFREG|0600 || st.Uid != 1000 || st.Gid != 1000 || st.Nlink != 1 {
		return ErrMismatch
	}
	phase = "ro-private-source"
	if data, err := os.ReadFile(nfsSourceClientsQEMU + "/archive/marker"); err != nil || string(data) != "phantowd-source-private-ro\n" {
		return ErrMismatch
	}
	file, err = os.OpenFile(nfsSourceClientsQEMU+"/archive/must-not-exist", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if file != nil {
		_ = file.Close()
	}
	if !errors.Is(err, unix.EROFS) {
		return ErrMismatch
	}
	missing, err := unix.Openat2(int(o.data[1].Fd()), "must-not-exist", &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV})
	if err == nil {
		_ = unix.Close(missing)
		return ErrMismatch
	}
	if !errors.Is(err, unix.ENOENT) {
		return err
	}
	if o.sourceLoss {
		phase = "source-loss"
		o.accessComplete = true
		return o.exerciseSourceLossQEMU(ctx)
	}
	phase = "unmount-clients"
	for len(o.mounts) > 0 {
		index := len(o.mounts) - 1
		mount := o.mounts[index]
		if err := unix.Unmount(mount.path, 0); err != nil {
			return err
		}
		var current unix.Statx_t
		if sourceClientStatQEMU(mount.path, &current) != nil || !sameMountdChannelQEMU(current, mount.before) {
			return ErrReviewRequired
		}
		o.mounts = o.mounts[:index]
	}
	phase = "withdraw-exports"
	if err := o.export(ctx, s, processowner.NFSSourceWithdrawQEMU); err != nil {
		return err
	}
	if err := o.export(ctx, s, processowner.NFSSourceFlushQEMU); err != nil {
		return err
	}
	table, err := os.ReadFile(nfsStateViewQEMU + "/nfs/etab")
	if err != nil || len(table) != 0 {
		return ErrMismatch
	}
	o.exportsLoaded = false
	o.accessComplete = true
	fmt.Println("PHANTOWD_NFS_SOURCE_IO_READY original_sources=true private_0700=true rw=true ro_read=true ro_erofs=true denied_client=true anon_uid_gid=1000 fsynced=true clients_unmounted=true exports_withdrawn=true product=false scope=qemu-only")
	return nil
}

func (o *NFSSourceAccessQEMU) checkView(pid int) error {
	const mask = unix.STATX_BASIC_STATS | unix.STATX_MNT_ID_UNIQUE
	root := fmt.Sprintf("/proc/%d/root", pid)
	var anchor unix.Statx_t
	var anchorFS unix.Statfs_t
	if unix.Statx(unix.AT_FDCWD, root+nfsSourceAnchorQEMU, 0, mask, &anchor) != nil || anchor.Mask&mask != mask ||
		anchor.Ino != o.volumeMetadata.Ino || anchor.Dev_major != o.volumeMetadata.Dev_major || anchor.Dev_minor != o.volumeMetadata.Dev_minor ||
		anchor.Mnt_id == o.volumeMetadata.Mnt_id || unix.Statfs(root+nfsSourceAnchorQEMU, &anchorFS) != nil || anchorFS.Type != unix.EXT4_SUPER_MAGIC || anchorFS.Flags&unix.ST_RDONLY == 0 {
		return ErrMismatch
	}
	for index, name := range nfsSourceDataNamesQEMU {
		var st unix.Statx_t
		var fs unix.Statfs_t
		path := root + nfsSourceAnchorQEMU + "/" + name
		original := o.metadata[index]
		if unix.Statx(unix.AT_FDCWD, path, 0, mask, &st) != nil || st.Mask&mask != mask || st.Ino != original.Ino || st.Dev_major != original.Dev_major || st.Dev_minor != original.Dev_minor || st.Mode != original.Mode || st.Uid != 1000 || st.Gid != 1000 || st.Mnt_id == original.Mnt_id || unix.Statfs(path, &fs) != nil || fs.Type != unix.EXT4_SUPER_MAGIC {
			return ErrMismatch
		}
		if (fs.Flags&unix.ST_RDONLY != 0) != (index != 0) {
			return ErrMismatch
		}
	}
	for index, name := range []string{"filehandle", "export_features"} {
		var st unix.Statx_t
		original := o.controlMetadata[index+1]
		if unix.Statx(unix.AT_FDCWD, root+"/proc/fs/nfsd/"+name, 0, mask, &st) != nil || st.Ino != original.Ino || st.Dev_major != original.Dev_major || st.Dev_minor != original.Dev_minor || st.Mnt_id == original.Mnt_id {
			return ErrMismatch
		}
	}
	for _, name := range []string{"/dev", "/sys", "/proc/self", "/proc/fs/nfsd/threads", "/proc/fs/nfsd/portlist"} {
		if _, err := os.Lstat(root + name); !errors.Is(err, os.ErrNotExist) {
			return ErrMismatch
		}
	}
	return nil
}

func cleanNFSSourceStateQEMU() error {
	entries, err := os.ReadDir(nfsStateViewQEMU + "/nfs")
	if err != nil || len(entries) > 8 {
		return ErrReviewRequired
	}
	allowed := map[string]bool{"etab": true, "rmtab": true, ".etab.lock": true, ".rmtab.lock": true}
	for _, entry := range entries {
		if !allowed[entry.Name()] {
			return ErrMismatch
		}
		path := nfsStateViewQEMU + "/nfs/" + entry.Name()
		var st unix.Stat_t
		if unix.Lstat(path, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Uid != 0 || st.Gid != 0 {
			return ErrMismatch
		}
		if err := os.Remove(path); err != nil {
			return err
		}
	}
	for _, name := range nfsSourceDataNamesQEMU {
		if err := os.Remove(nfsSourceClientsQEMU + "/" + name); err != nil {
			return err
		}
	}
	if err := os.Remove(nfsSourceClientsQEMU); err != nil {
		return err
	}
	return os.Remove(nfsSourceInputQEMU)
}
