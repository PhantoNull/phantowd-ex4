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

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"golang.org/x/sys/unix"
)

// Fixed disposable source consumer. The trusted source Owner supplies ORIGINAL
// directory descriptors at CONSTRUCTION, never via an operation or getter.
// This does not establish product policy/identity or sole kernel-domain authority.
type NFSSourceAccessQEMU struct {
	heldClientIdentity                unix.Stat_t
	original                          *NFSSourceAccessQEMU
	gate                              chan struct{}
	lease                             *NFSInputLeaseQEMU
	data                              [3]*os.File
	metadata                          [3]unix.Statx_t
	volume                            *os.File
	volumeMetadata                    unix.Statx_t
	controlRoot                       *os.File
	filehandle, features              *os.File
	controlMetadata                   [3]unix.Statx_t
	channels                          *NFSMountdChannelsQEMU
	bootstrap, input                  *os.File
	clientCode                        *os.File
	capture                           *processowner.CaptureOwner
	consumed, settled, closed, review bool
	exportsLoaded                     bool
	accessComplete                    bool
	sourceLoss, lossTriggered         bool
	loss                              *nfsSourceLossEvidenceQEMU
	heldClient, faultFile             *os.File
	bindingUncertain                  *os.File
	cause                             error
	mounts                            []nfsSourceClientMountQEMU
}

type nfsSourceClientMountQEMU struct {
	path   string
	before unix.Statx_t
}

var nfsSourceDataNamesQEMU = [...]string{"books", "archive", "denied"}

const nfsSourceAnchorQEMU = "/srv/phantowd/volumes/qemu-plan"
const nfsSourceInputQEMU = "/run/nfs-source-empty-input"

func NewNFSSourceAccessQEMU(ctx context.Context, lease *NFSInputLeaseQEMU, sources [4]*os.File) (_ *NFSSourceAccessQEMU, result error) {
	return newNFSSourceAccessQEMU(ctx, lease, sources, false)
}

func NewNFSSourceLossAccessQEMU(ctx context.Context, lease *NFSInputLeaseQEMU, sources [4]*os.File) (*NFSSourceAccessQEMU, error) {
	return newNFSSourceAccessQEMU(ctx, lease, sources, true)
}

func newNFSSourceAccessQEMU(ctx context.Context, lease *NFSInputLeaseQEMU, sources [4]*os.File, sourceLoss bool) (_ *NFSSourceAccessQEMU, result error) {
	if ctx == nil || nfsCodeGuardQEMU() != nil || !nfsSourceAccessSelectorQEMU(sourceLoss) || lease == nil {
		return nil, ErrInvalid
	}
	if err := lease.enter(ctx); err != nil {
		return nil, err
	}
	defer func() { <-lease.gate }()
	if lease.closed || lease.review || lease.consumer != nil {
		return nil, ErrUnavailable
	}
	s, err := lease.parent.code.enter(ctx)
	if err != nil {
		return nil, err
	}
	defer s.leave()
	if err := lease.revalidate(ctx, s); err != nil {
		return nil, err
	}
	enabled, _, roots, err := lease.parent.candidate.Documents()
	if err != nil || !enabled || len(roots) != 3 {
		return nil, ErrMismatch
	}
	for i, root := range roots {
		if root.RelativePath != nfsSourceDataNamesQEMU[i] || root.Volume.MountPath != nfsSourceAnchorQEMU || root.ReadOnly != (i != 0) {
			return nil, ErrMismatch
		}
	}
	o := &NFSSourceAccessQEMU{gate: make(chan struct{}, 1), lease: lease}
	o.sourceLoss = sourceLoss
	o.original = o
	lease.consumer = o
	defer func() {
		if result != nil {
			result = constructionRollback(result, o, func() error {
				if err := o.release(); err != nil {
					return err
				}
				lease.consumer = nil
				return nil
			})
		}
	}()
	for i, file := range sources[:3] {
		o.data[i], err = duplicateNFSSourceQEMU(file)
		if err != nil {
			return nil, err
		}
		if err := nfsSourceMetadataQEMU(o.data[i], unix.EXT4_SUPER_MAGIC, unix.S_IFDIR|0700, &o.metadata[i]); err != nil {
			return nil, err
		}
		st := o.metadata[i]
		v := roots[i].Volume
		if st.Uid != 1000 || st.Gid != 1000 || st.Mnt_id != v.MountID || st.Dev_major != v.DeviceMajor || st.Dev_minor != v.DeviceMinor {
			return nil, ErrMismatch
		}
	}
	o.volume, err = duplicateNFSSourceQEMU(sources[3])
	if err != nil {
		return nil, err
	}
	if err := nfsSourceMetadataQEMU(o.volume, unix.EXT4_SUPER_MAGIC, 0, &o.volumeMetadata); err != nil {
		return nil, err
	}
	v, st := roots[0].Volume, o.volumeMetadata
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 || st.Gid != 0 || st.Mnt_id != v.MountID || st.Dev_major != v.DeviceMajor || st.Dev_minor != v.DeviceMinor {
		return nil, ErrMismatch
	}
	fd, err := unix.Open("/proc/fs/nfsd", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	o.controlRoot = os.NewFile(uintptr(fd), "nfs-source-original-control")
	if err := nfsSourceMetadataQEMU(o.controlRoot, 0x6e667364, 0, &o.controlMetadata[0]); err != nil {
		return nil, err
	}
	for i, name := range []string{"filehandle", "export_features"} {
		fd, err := unix.Openat2(int(o.controlRoot.Fd()), name, &unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV})
		if err != nil {
			return nil, err
		}
		f := os.NewFile(uintptr(fd), "nfs-source-original-control-leaf")
		if i == 0 {
			o.filehandle = f
		} else {
			o.features = f
		}
		mode := uint16(unix.S_IFREG | 0600)
		if i == 1 {
			mode = unix.S_IFREG | 0444
		}
		if err := nfsSourceMetadataQEMU(f, 0x6e667364, mode, &o.controlMetadata[i+1]); err != nil {
			return nil, err
		}
	}
	o.channels, err = newNFSMountdChannelsQEMU(ctx, true)
	if err != nil {
		return nil, err
	}
	o.bootstrap, err = os.Open("/usr/sbin/phantowd-nfs-table-bootstrap")
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(nfsSourceInputQEMU, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
	if err != nil {
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	o.input, err = os.Open(nfsSourceInputQEMU)
	if err != nil {
		return nil, err
	}
	if err := o.check(ctx); err != nil {
		return nil, err
	}
	return o, nil
}

func duplicateNFSSourceQEMU(file *os.File) (*os.File, error) {
	if file == nil {
		return nil, ErrInvalid
	}
	raw, err := file.SyscallConn()
	if err != nil {
		return nil, err
	}
	fd := -1
	var dupErr error
	if err := raw.Control(func(value uintptr) { fd, dupErr = unix.FcntlInt(value, unix.F_DUPFD_CLOEXEC, 0) }); err != nil || dupErr != nil || fd < 0 {
		return nil, ErrInvalid
	}
	return os.NewFile(uintptr(fd), "nfs-source-retained-role"), nil
}

func nfsSourceMetadataQEMU(file *os.File, kind int64, mode uint16, st *unix.Statx_t) error {
	if file == nil {
		return ErrMismatch
	}
	const mask = unix.STATX_BASIC_STATS | unix.STATX_MNT_ID_UNIQUE
	fd := int(file.Fd())
	flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
	var fs unix.Statfs_t
	if err != nil || flags&unix.O_PATH == 0 || unix.Fstatfs(fd, &fs) != nil || int64(fs.Type) != kind || unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_NO_AUTOMOUNT, mask, st) != nil || st.Mask&mask != mask || st.Ino == 0 || st.Mnt_id == 0 {
		return ErrMismatch
	}
	if mode != 0 && st.Mode != mode {
		return ErrMismatch
	}
	return nil
}

func (o *NFSSourceAccessQEMU) check(ctx context.Context) error {
	if o.review {
		return ErrReviewRequired
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	err := o.checkReferences(ctx)
	if err == nil {
		err = o.checkSourceBindings(ctx)
	}
	if err != nil {
		o.review = true
		if o.cause == nil {
			o.cause = err
		}
	}
	return err
}

func (o *NFSSourceAccessQEMU) checkReferences(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var volume unix.Statx_t
	if nfsSourceMetadataQEMU(o.volume, unix.EXT4_SUPER_MAGIC, 0, &volume) != nil || !sameMountdChannelQEMU(volume, o.volumeMetadata) {
		return ErrMismatch
	}
	for i, file := range o.data {
		var st unix.Statx_t
		if nfsSourceMetadataQEMU(file, unix.EXT4_SUPER_MAGIC, unix.S_IFDIR|0700, &st) != nil || !sameMountdChannelQEMU(st, o.metadata[i]) {
			return ErrMismatch
		}
	}
	for i, file := range []*os.File{o.controlRoot, o.filehandle, o.features} {
		var st unix.Statx_t
		if nfsSourceMetadataQEMU(file, 0x6e667364, 0, &st) != nil || !sameMountdChannelQEMU(st, o.controlMetadata[i]) {
			return ErrMismatch
		}
	}
	return o.channels.Check(ctx)
}

// Compare each current name BENEATH the original volume with the original
// directory tuple. Held-FD metadata alone cannot detect a renamed/replaced leaf.
// No storage-owner callback, absolute path reopen or authority getter is used.
func (o *NFSSourceAccessQEMU) checkSourceBindings(ctx context.Context) error {
	if o.bindingUncertain != nil {
		return ErrReviewRequired
	}
	for index, name := range nfsSourceDataNamesQEMU {
		if err := ctx.Err(); err != nil {
			return err
		}
		fd, err := unix.Openat2(int(o.volume.Fd()), name, &unix.OpenHow{Flags: unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV})
		if err != nil {
			return errors.Join(ErrMismatch, err)
		}
		current := os.NewFile(uintptr(fd), "nfs-source-current-binding")
		var st unix.Statx_t
		readErr := nfsSourceMetadataQEMU(current, unix.EXT4_SUPER_MAGIC, unix.S_IFDIR|0700, &st)
		if err := current.Close(); err != nil {
			o.bindingUncertain = current // Never retry Close on a recycled FD number.
			return errors.Join(ErrReviewRequired, readErr, err)
		}
		if readErr != nil || !sameMountdChannelQEMU(st, o.metadata[index]) {
			return errors.Join(ErrMismatch, readErr)
		}
	}
	return ctx.Err()
}

func (o *NFSSourceAccessQEMU) enter(ctx context.Context) error {
	if o == nil || o.original != o || o.gate == nil || ctx == nil {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case o.gate <- struct{}{}:
		return nil
	default:
		return processowner.ErrBusy
	}
}

func (o *NFSSourceAccessQEMU) Run(ctx context.Context) (result error) {
	if err := o.enter(ctx); err != nil {
		return err
	}
	defer func() { <-o.gate }()
	if err := o.lease.enter(ctx); err != nil {
		return err
	}
	defer func() { <-o.lease.gate }()
	if o.closed || o.consumed || o.review {
		return ErrUnavailable
	}
	s, err := o.lease.parent.code.enter(ctx)
	if err != nil {
		return err
	}
	defer s.leave()
	defer func() {
		if result != nil {
			o.review = true
			if o.cause == nil {
				o.cause = result
			}
			if !s.review {
				s.review = true
				s.cause = result
			}
		}
	}()
	if o.lease.consumer != o || s.sourceAccess != nil || o.lease.revalidate(ctx, s) != nil || o.check(ctx) != nil {
		return ErrReviewRequired
	}
	o.consumed = true
	s.sourceAccess = o
	if err := probeNFSRPCBindLockedQEMU(ctx, o.lease.parent, s); err != nil {
		return err
	}
	if o.capture != nil || len(o.mounts) != 0 || o.exportsLoaded || o.check(ctx) != nil {
		return ErrReviewRequired
	}
	o.settled = true
	return nil
}

func (o *NFSSourceAccessQEMU) Close(ctx context.Context) error {
	if err := o.enter(ctx); err != nil {
		return err
	}
	defer func() { <-o.gate }()
	if err := o.lease.enter(ctx); err != nil {
		return err
	}
	defer func() { <-o.lease.gate }()
	if o.closed {
		return nil
	}
	if o.review || o.consumed && !o.settled {
		return ErrReviewRequired
	}
	s, err := o.lease.parent.code.enter(ctx)
	if err != nil {
		return err
	}
	defer s.leave()
	if o.check(ctx) != nil || o.lease.revalidate(ctx, s) != nil {
		return ErrReviewRequired
	}
	if s.sourceAccess == o {
		s.sourceAccess = nil
	}
	if err := o.release(); err != nil {
		o.review = true
		o.cause = err
		s.review = true
		s.cause = err
		return ErrReviewRequired
	}
	if o.consumed {
		if err := cleanNFSSourceStateQEMU(); err != nil {
			o.review = true
			o.cause = err
			s.review = true
			s.cause = err
			return ErrReviewRequired
		}
	}
	o.closed = true
	return nil
}

func nfsSourceAccessSelectorQEMU(sourceLoss bool) bool {
	command, err := os.ReadFile("/proc/cmdline")
	if err != nil || len(command) > 4096 {
		return false
	}
	count, loss := 0, 0
	for _, word := range strings.Fields(string(command)) {
		if word == "phantowd_nfs_source_fixture=1" {
			count++
		}
		if strings.HasPrefix(word, "phantowd_nfs_source_loss_fixture=") {
			if word != "phantowd_nfs_source_loss_fixture=1" {
				return false
			}
			loss++
		}
	}
	wantLoss := 0
	if sourceLoss {
		wantLoss = 1
	}
	return count == 1 && loss == wantLoss
}

func (o *NFSSourceAccessQEMU) release() error {
	if o.bindingUncertain != nil || o.heldClient != nil || o.faultFile != nil {
		return ErrReviewRequired
	}
	if o.channels != nil {
		if err := o.channels.Close(); err != nil {
			return err
		}
		o.channels = nil
	}
	for i, f := range o.data {
		if f != nil {
			if err := f.Close(); err != nil {
				return err
			}
			o.data[i] = nil
		}
	}
	for _, slot := range []**os.File{&o.volume, &o.filehandle, &o.features, &o.controlRoot, &o.input, &o.bootstrap, &o.clientCode} {
		if *slot != nil {
			if err := (*slot).Close(); err != nil {
				return err
			}
			*slot = nil
		}
	}
	return nil
}

func (NFSSourceAccessQEMU) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
func (*NFSSourceAccessQEMU) UnmarshalJSON([]byte) error  { return ErrInvalid }
func (NFSSourceAccessQEMU) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "nfs-source-access{private}")
}
